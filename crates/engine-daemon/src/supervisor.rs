use deepdoc_protocol::framing::async_codec::{read_frame_async, write_frame_async};
use deepdoc_protocol::{FailureKind, WorkerCapabilities, WorkerRequest, WorkerResponse};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, Notify};

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
}

impl WorkerProcess {
    async fn spawn(exe: &PathBuf, job: Option<&Arc<JobObjectGuard>>) -> Result<Self, String> {
        let mut cmd = Command::new(exe);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
            cmd.creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);
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

struct PoolState {
    idle: VecDeque<WorkerProcess>,
    live_count: usize,
}

pub struct WorkerPool {
    exe_path: PathBuf,
    #[cfg(windows)]
    job: Option<Arc<JobObjectGuard>>,
    state: Mutex<PoolState>,
    notify: Notify,
    max_size: usize,
    ocr_warmup: Mutex<Arc<Vec<(String, String)>>>,
}

impl WorkerPool {
    /// Start an elastic worker pool that spawns workers lazily up to `max_size`
    /// and can shrink idle workers to `0` after scan jobs complete.
    pub async fn start(exe_path: PathBuf, max_size: usize) -> Result<Arc<Self>, String> {
        let max_size = max_size.max(1);
        #[cfg(windows)]
        let job = create_sandbox_job().map(Arc::new);

        if !exe_path.exists() {
            // Verify spawnability cleanly on Windows PATH fallback if relative name was passed
            let test_wp = WorkerProcess::spawn(&exe_path, job.as_ref()).await?;
            let mut deque = VecDeque::with_capacity(max_size);
            deque.push_back(test_wp);
            return Ok(Arc::new(Self {
                exe_path,
                #[cfg(windows)]
                job,
                state: Mutex::new(PoolState {
                    idle: deque,
                    live_count: 1,
                }),
                notify: Notify::new(),
                max_size,
                ocr_warmup: Mutex::new(Arc::new(Vec::new())),
            }));
        }

        Ok(Arc::new(Self {
            exe_path,
            #[cfg(windows)]
            job,
            state: Mutex::new(PoolState {
                idle: VecDeque::with_capacity(max_size),
                live_count: 0,
            }),
            notify: Notify::new(),
            max_size,
            ocr_warmup: Mutex::new(Arc::new(Vec::new())),
        }))
    }

    /// Update persistent OCR cache warmup entries for newly spawned (and currently idle) workers.
    pub async fn set_ocr_warmup(&self, entries: Arc<Vec<(String, String)>>) {
        *self.ocr_warmup.lock().await = entries.clone();
        if entries.is_empty() {
            return;
        }
        let existing_idle = {
            let mut st = self.state.lock().await;
            st.idle.drain(..).collect::<Vec<_>>()
        };
        let req = WorkerRequest::WarmOcrCache {
            entries: (*entries).clone(),
        };
        for mut wp in existing_idle {
            if wp.call(&req, Duration::from_secs(5)).await.is_ok() {
                self.release(wp).await;
            } else {
                self.retire_broken(wp).await;
            }
        }
    }

    /// Release idle worker processes down to `keep` so resident OCR/PDFium RAM is freed when idle.
    pub async fn shrink_idle(&self, keep: usize) {
        let mut to_kill = Vec::new();
        {
            let mut st = self.state.lock().await;
            while st.idle.len() > keep {
                if let Some(wp) = st.idle.pop_back() {
                    st.live_count = st.live_count.saturating_sub(1);
                    to_kill.push(wp);
                }
            }
        }
        for mut wp in to_kill {
            let _ = wp.child.kill().await;
        }
        self.notify.notify_waiters();
    }

    async fn acquire(&self) -> Result<WorkerProcess, String> {
        loop {
            let should_spawn = {
                let mut st = self.state.lock().await;
                if let Some(wp) = st.idle.pop_front() {
                    return Ok(wp);
                }
                if st.live_count < self.max_size {
                    st.live_count += 1;
                    true
                } else {
                    false
                }
            };

            if should_spawn {
                match WorkerProcess::spawn(&self.exe_path, self.job.as_ref()).await {
                    Ok(mut wp) => {
                        let warmup = self.ocr_warmup.lock().await.clone();
                        if !warmup.is_empty() {
                            let req = WorkerRequest::WarmOcrCache {
                                entries: (*warmup).clone(),
                            };
                            let _ = wp.call(&req, Duration::from_secs(5)).await;
                        }
                        return Ok(wp);
                    }
                    Err(e) => {
                        let mut st = self.state.lock().await;
                        st.live_count = st.live_count.saturating_sub(1);
                        drop(st);
                        self.notify.notify_one();
                        return Err(e);
                    }
                }
            }
            self.notify.notified().await;
        }
    }

    async fn release(&self, wp: WorkerProcess) {
        let excess = {
            let mut st = self.state.lock().await;
            if st.idle.len() < self.max_size {
                st.idle.push_back(wp);
                None
            } else {
                st.live_count = st.live_count.saturating_sub(1);
                Some(wp)
            }
        };
        if let Some(mut extra) = excess {
            let _ = extra.child.kill().await;
        }
        self.notify.notify_one();
    }

    async fn retire_broken(&self, mut wp: WorkerProcess) {
        let _ = wp.child.kill().await;
        {
            let mut st = self.state.lock().await;
            st.live_count = st.live_count.saturating_sub(1);
        }
        self.notify.notify_one();
    }

    pub async fn health_check(&self) -> Result<WorkerCapabilities, String> {
        let mut wp = self.acquire().await?;
        let res = wp
            .call(&WorkerRequest::HealthCheck, Duration::from_secs(5))
            .await;
        match res {
            Ok(WorkerResponse::Health { capabilities }) => {
                self.release(wp).await;
                Ok(capabilities)
            }
            Ok(_) => {
                self.release(wp).await;
                Err("unexpected health response".into())
            }
            Err(e) => {
                self.retire_broken(wp).await;
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
            WorkerRequest::HealthCheck | WorkerRequest::WarmOcrCache { .. } => (0, String::new()),
        };

        let mut wp = match self.acquire().await {
            Ok(w) => w,
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
                self.release(wp).await;
                resp
            }
            Err(err) => {
                let kind = if err.contains("timeout") {
                    FailureKind::Timeout
                } else {
                    FailureKind::InternalError
                };
                self.retire_broken(wp).await;
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
