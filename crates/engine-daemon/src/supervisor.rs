use deepdoc_protocol::framing::async_codec::{read_frame_async, write_frame_async};
use deepdoc_protocol::{FailureKind, WorkerCapabilities, WorkerRequest, WorkerResponse};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const MAX_TASKS_PER_WORKER: usize = 2500;

#[cfg(windows)]
struct JobObjectGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for JobObjectGuard {}
#[cfg(windows)]
unsafe impl Sync for JobObjectGuard {}

#[cfg(windows)]
impl Drop for JobObjectGuard {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(windows)]
fn create_sandbox_job() -> Option<JobObjectGuard> {
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };

    unsafe {
        let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if h.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        // 2 GiB hard virtual/commit cap per sandbox worker
        info.ProcessMemoryLimit = 2 * 1024 * 1024 * 1024;
        SetInformationJobObject(
            h,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        Some(JobObjectGuard(h))
    }
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    tasks_handled: usize,
}

impl WorkerProcess {
    async fn spawn(
        exe: &PathBuf,
        job: Option<&Arc<JobObjectGuard>>,
        low_resource: bool,
    ) -> Result<Self, String> {
        let mut cmd = Command::new(exe);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            const IDLE_PRIORITY_CLASS: u32 = 0x0000_0040;
            let prio = if low_resource { IDLE_PRIORITY_CLASS } else { 0 };
            cmd.creation_flags(CREATE_NO_WINDOW | prio);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn `{}`: {e}", exe.display()))?;

        #[cfg(windows)]
        if let (Some(j), Some(pid)) = (job, child.id()) {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
            unsafe {
                let proc_h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
                if !proc_h.is_null() {
                    let _ = AssignProcessToJobObject(j.0, proc_h);
                    CloseHandle(proc_h);
                }
            }
        }

        let stdin = child.stdin.take().ok_or("missing child stdin")?;
        let stdout = child.stdout.take().ok_or("missing child stdout")?;
        Ok(Self {
            child,
            stdin,
            stdout,
            tasks_handled: 0,
        })
    }

    async fn call(
        &mut self,
        req: &WorkerRequest,
        timeout: Duration,
    ) -> Result<WorkerResponse, String> {
        let fut = async {
            write_frame_async(&mut self.stdin, req)
                .await
                .map_err(|e| format!("worker write error: {e}"))?;
            read_frame_async::<_, WorkerResponse>(&mut self.stdout)
                .await
                .map_err(|e| format!("worker read error: {e}"))
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(res) => res,
            Err(_) => {
                let _ = self.child.kill().await;
                Err("worker timeout".into())
            }
        }
    }
}

pub struct WorkerPool {
    exe_path: PathBuf,
    #[cfg(windows)]
    job: Option<Arc<JobObjectGuard>>,
    idle: Mutex<VecDeque<WorkerProcess>>,
    slots: Arc<Semaphore>,
    max_size: usize,
    ocr_warmup: Mutex<Arc<Vec<(String, String)>>>,
    low_resource: AtomicBool,
}

impl WorkerPool {
    /// Start an elastic worker pool that spawns workers lazily up to `max_size`
    /// and can shrink idle workers to `0` after scan jobs complete.
    pub async fn start(exe_path: PathBuf, max_size: usize) -> Result<Arc<Self>, String> {
        let max_size = max_size.max(1);
        #[cfg(windows)]
        let job = create_sandbox_job().map(Arc::new);

        let mut deque = VecDeque::with_capacity(max_size);
        if !exe_path.exists() {
            // Verify spawnability cleanly on Windows PATH fallback if relative name was passed
            let test_wp = WorkerProcess::spawn(&exe_path, job.as_ref(), false).await?;
            deque.push_back(test_wp);
        }

        Ok(Arc::new(Self {
            exe_path,
            #[cfg(windows)]
            job,
            idle: Mutex::new(deque),
            slots: Arc::new(Semaphore::new(max_size)),
            max_size,
            ocr_warmup: Mutex::new(Arc::new(Vec::new())),
            low_resource: AtomicBool::new(false),
        }))
    }

    /// Toggle idle-priority (`IDLE_PRIORITY_CLASS`) worker scheduling for low CPU/RAM footprint indexing.
    pub async fn set_low_resource(&self, enabled: bool) {
        let prev = self.low_resource.swap(enabled, Ordering::Relaxed);
        if prev != enabled || enabled {
            self.shrink_idle(0).await;
        }
    }

    /// Update persistent OCR cache warmup entries for newly spawned (and currently idle) workers.
    pub async fn set_ocr_warmup(&self, entries: Arc<Vec<(String, String)>>) {
        *self.ocr_warmup.lock().await = entries.clone();
        if entries.is_empty() {
            return;
        }
        let existing_idle = {
            let mut idle = self.idle.lock().await;
            idle.drain(..).collect::<Vec<_>>()
        };
        let req = WorkerRequest::WarmOcrCache {
            entries: (*entries).clone(),
        };
        for mut wp in existing_idle {
            if wp.call(&req, Duration::from_secs(5)).await.is_ok() {
                let mut idle = self.idle.lock().await;
                if idle.len() < self.max_size {
                    idle.push_back(wp);
                } else {
                    drop(idle);
                    let _ = wp.child.kill().await;
                }
            } else {
                let _ = wp.child.kill().await;
            }
        }
    }

    /// Release idle worker processes down to `keep` so resident OCR/PDFium RAM is freed when idle.
    pub async fn shrink_idle(&self, keep: usize) {
        let to_kill = {
            let mut idle = self.idle.lock().await;
            let mut drained = Vec::new();
            while idle.len() > keep {
                if let Some(wp) = idle.pop_back() {
                    drained.push(wp);
                }
            }
            drained
        };
        for mut wp in to_kill {
            let _ = wp.child.kill().await;
        }
    }

    async fn acquire(&self) -> Result<(OwnedSemaphorePermit, WorkerProcess), String> {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "worker pool closed".to_string())?;

        if let Some(wp) = self.idle.lock().await.pop_front() {
            return Ok((permit, wp));
        }

        let low_res = self.low_resource.load(Ordering::Relaxed);
        let mut wp = WorkerProcess::spawn(&self.exe_path, self.job.as_ref(), low_res).await?;
        let warmup = self.ocr_warmup.lock().await.clone();
        if !warmup.is_empty() {
            let req = WorkerRequest::WarmOcrCache {
                entries: (*warmup).clone(),
            };
            let _ = wp.call(&req, Duration::from_secs(5)).await;
        }
        Ok((permit, wp))
    }

    async fn release(&self, permit: OwnedSemaphorePermit, mut wp: WorkerProcess, count_task: bool) {
        if count_task {
            wp.tasks_handled += 1;
        }
        let excess = if wp.tasks_handled >= MAX_TASKS_PER_WORKER {
            Some(wp)
        } else {
            let mut idle = self.idle.lock().await;
            if idle.len() < self.max_size {
                idle.push_back(wp);
                None
            } else {
                Some(wp)
            }
        };
        if let Some(mut old) = excess {
            let _ = old.child.kill().await;
        }
        drop(permit);
    }

    async fn retire_broken(&self, permit: OwnedSemaphorePermit, mut wp: WorkerProcess) {
        let _ = wp.child.kill().await;
        drop(permit);
    }

    pub async fn health_check(&self) -> Result<WorkerCapabilities, String> {
        let (permit, mut wp) = self.acquire().await?;
        let res = wp
            .call(&WorkerRequest::HealthCheck, Duration::from_secs(5))
            .await;
        match res {
            Ok(WorkerResponse::Health { capabilities }) => {
                self.release(permit, wp, false).await;
                Ok(capabilities)
            }
            Ok(_) => {
                self.release(permit, wp, false).await;
                Err("unexpected health response".into())
            }
            Err(e) => {
                self.retire_broken(permit, wp).await;
                Err(e)
            }
        }
    }

    pub async fn execute_parse(
        &self,
        req: WorkerRequest,
        timeout: Duration,
    ) -> WorkerResponse {
        let (task_id, virtual_path) = match &req {
            WorkerRequest::ParseFile {
                task_id,
                virtual_path,
                ..
            }
            | WorkerRequest::ParseBytes {
                task_id,
                virtual_path,
                ..
            } => (*task_id, virtual_path.clone()),
            WorkerRequest::OcrImageBytes { task_id, label, .. } => (*task_id, label.clone()),
            WorkerRequest::OcrPdfPages {
                task_id, disk_path, ..
            } => (*task_id, disk_path.clone()),
            WorkerRequest::ParseFilesBatch { task_id, .. } => (*task_id, "batch".into()),
            WorkerRequest::HealthCheck | WorkerRequest::WarmOcrCache { .. } => (0, String::new()),
        };

        let (permit, mut wp) = match self.acquire().await {
            Ok(pair) => pair,
            Err(e) => {
                return WorkerResponse::Failed {
                    task_id,
                    virtual_path,
                    kind: FailureKind::InternalError,
                    detail: e,
                }
            }
        };

        match wp.call(&req, timeout).await {
            Ok(resp) => {
                self.release(permit, wp, true).await;
                resp
            }
            Err(err) => {
                let kind = if err.contains("timeout") {
                    FailureKind::Timeout
                } else {
                    FailureKind::InternalError
                };
                self.retire_broken(permit, wp).await;
                WorkerResponse::Failed {
                    task_id,
                    virtual_path,
                    kind,
                    detail: format!("sandbox worker crashed/timed out and was recycled: {err}"),
                }
            }
        }
    }
}

pub fn find_sibling_exe(name: &str) -> PathBuf {
    if let Ok(cur) = std::env::current_exe() {
        if let Some(dir) = cur.parent() {
            let cand = dir.join(name);
            if cand.exists() {
                return cand;
            }
        }
    }
    PathBuf::from(name)
}
