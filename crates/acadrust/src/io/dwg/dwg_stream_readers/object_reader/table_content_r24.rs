//! R24+ (AC1027+) TABLECONTENT reader.
//!
//! Reads the AcDbTableContent data stream embedded in R24+ ACAD_TABLE
//! entities (replacing the old inline cell format).
//!
//! Inheritance chain (all inlined):
//!   AcDbLinkedData
//!     → AcDbLinkedTableData (columns, rows, cells)
//!       → AcDbFormattedTableData (merged ranges, margins, styles)
//!         → AcDbTableContent (additional fields)
//!
//! Reference: Open Design Specification for .dwg files §20.4.97

use crate::io::dwg::dwg_stream_readers::merged_reader::DwgMergedReader;
use crate::io::dwg::dwg_version::DwgVersion;
use crate::types::DxfVersion;

/// Cell value types
#[derive(Debug, Clone, PartialEq)]
pub enum CellValue {
    String(String),
    Double(f64),
    Long(i32),
    Unknown,
}

/// A single cell's content
#[derive(Debug, Clone)]
pub struct TableContentCell {
    pub cell_type: i32,      // 0=Unknown, 1=Value, 2=Field, 4=Block
    pub value: CellValue,
    pub tooltip: String,
}

/// A row of cells
#[derive(Debug, Clone)]
pub struct TableContentRow {
    pub cells: Vec<TableContentCell>,
}

/// Parsed R24+ table content data (minimal: only cell text).
#[derive(Debug, Clone)]
pub struct TableContentR24 {
    pub num_columns: i32,
    pub num_rows: i32,
    pub column_widths: Vec<f64>,
    pub row_heights: Vec<f64>,
    pub rows: Vec<TableContentRow>,
}

/// Read a cell value block (§20.4.98).
fn read_cell_value(reader: &mut DwgMergedReader) -> CellValue {
    let value_type = reader.read_bit_long();   // BL
    let _unit_type = reader.read_bit_long();   // BL
    let _flags = reader.read_bit_long();       // BL

    match value_type {
        1 => {
            // Long
            let _long_val = reader.read_bit_long();
            let _fmt = reader.read_variable_text();
            let _display = reader.read_variable_text();
            CellValue::Long(_long_val)
        }
        2 => {
            // Double
            let d = reader.read_bit_double();
            let _fmt = reader.read_variable_text();
            let _display = reader.read_variable_text();
            CellValue::Double(d)
        }
        4 => {
            // String
            let s = reader.read_variable_text();
            let _fmt = reader.read_variable_text();
            let _display = reader.read_variable_text();
            CellValue::String(s)
        }
        _ => {
            // Unknown / other types — skip
            CellValue::Unknown
        }
    }
}

/// Read cell content items (may be multiple per cell).
fn read_cell_contents(reader: &mut DwgMergedReader, count: i32) -> Vec<TableContentCell> {
    let mut contents = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let content_type = reader.read_bit_long(); // BL 90
        match content_type {
            1 => {
                // Value payload is read below.
            }
            2 => {
                // Field — skip handle
                let _field_handle = reader.read_handle();
            }
            4 => {
                // Block — skip handle
                let _block_handle = reader.read_handle();
            }
            _ => {}
        }

        // If Value type, actually read the value
        let actual_value = if content_type == 1 {
            read_cell_value(reader)
        } else {
            CellValue::Unknown
        };

        contents.push(TableContentCell {
            cell_type: content_type,
            value: actual_value,
            tooltip: String::new(),
        });
    }
    contents
}

/// Read AcDbTableContent from the merged reader stream.
///
/// The reader should be positioned at the start of the
/// TABLECONTENT data (after the table entity's preamble
/// and version-specific prefix fields).
pub fn read_table_content_r24(
    reader: &mut DwgMergedReader,
    _version: DwgVersion,
    _dxf_version: DxfVersion,
) -> TableContentR24 {
    // ── AcDbLinkedData fields ──
    let _name = reader.read_variable_text();       // TV 1
    let _description = reader.read_variable_text(); // TV 300

    // ── AcDbLinkedTableData fields ──
    let num_cols = reader.read_bit_long();          // BL 90 — number of columns
    let mut column_widths = Vec::with_capacity(num_cols as usize);

    // Columns
    for _ in 0..num_cols {
        let _col_name = reader.read_variable_text();  // TV 300
        let _custom_data = reader.read_bit_long();    // BL 91
        // Cell style data (skip)
        let _cell_style_id = reader.read_bit_long();  // BL 90
        let col_width = reader.read_bit_double();     // BD 40
        column_widths.push(col_width);
    }

    // Rows
    let num_rows = reader.read_bit_long();           // BL 91
    let mut row_heights = Vec::with_capacity(num_rows as usize);
    let mut rows = Vec::with_capacity(num_rows as usize);

    for _ri in 0..num_rows {
        let cells_in_row = reader.read_bit_long();   // BL 90
        let mut row_cells = Vec::with_capacity(cells_in_row as usize);

        for _ci in 0..cells_in_row {
            // Cell state flags
            let _state_flags = reader.read_bit_long(); // BL 90
            let _tooltip = reader.read_variable_text(); // TV 300
            let _custom_data = reader.read_bit_long();  // BL 91
            let has_linked = reader.read_bit_long();    // BL 92

            // Linked data (skip)
            if has_linked != 0 {
                let _link_handle = reader.read_handle(); // H 340
                let _link_rows = reader.read_bit_long(); // BL 93
                let _link_cols = reader.read_bit_long(); // BL 94
                let _unknown = reader.read_bit_long();   // BL 96
            }

            // Cell contents
            let content_count = reader.read_bit_long(); // BL 95
            let contents = read_cell_contents(reader, content_count);

            // Take first content's text as the cell value
            let cell = if contents.is_empty() {
                TableContentCell {
                    cell_type: 0,
                    value: CellValue::Unknown,
                    tooltip: _tooltip,
                }
            } else {
                TableContentCell {
                    cell_type: contents[0].cell_type,
                    value: contents[0].value.clone(),
                    tooltip: _tooltip,
                }
            };
            row_cells.push(cell);
        }
        rows.push(TableContentRow { cells: row_cells });

        // Row cell style + height
        let _row_cell_style_id = reader.read_bit_long(); // BL 90
        let row_height = reader.read_bit_double();        // BD 40
        row_heights.push(row_height);
    }

    // ── AcDbFormattedTableData fields (skip for now) ──
    // Merged cell ranges
    let merged_count = reader.read_bit_long();
    for _ in 0..merged_count {
        let _ = reader.read_bit_long(); // start row
        let _ = reader.read_bit_long(); // start col
        let _ = reader.read_bit_long(); // end row
        let _ = reader.read_bit_long(); // end col
    }

    // Custom data count
    let _custom_count = reader.read_bit_long();

    // Cell style data (skip by reading cell style ID)
    let _cell_style_data_id = reader.read_bit_long();

    // Margins
    let _h_margin = reader.read_bit_double();
    let _v_margin = reader.read_bit_double();

    // Suppress flags
    let _suppress_title = reader.read_bit();
    let _suppress_header = reader.read_bit();

    // Row styles (data, title, header) — skip 3 iterations
    for _ in 0..3 {
        let _ts_handle = reader.read_handle();   // H 7
        let _text_height = reader.read_bit_double(); // BD 140
        let _alignment = reader.read_bit_short();    // BS 170
        let _text_color = reader.read_cm_color();
        let _fill_color = reader.read_cm_color();
        let _bg_enabled = reader.read_bit();

        // 6 borders
        for _ in 0..6 {
            let _lw = reader.read_bit_short();
            let _visible = reader.read_bit();
            let _border_color = reader.read_cm_color();
        }

        // Data type/unit
        let _data_type = reader.read_bit_long();
        let _data_unit = reader.read_bit_long();
        let _format_str = reader.read_variable_text();
    }

    TableContentR24 {
        num_columns: num_cols,
        num_rows,
        column_widths,
        row_heights,
        rows,
    }
}

// ════════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::dwg::dwg_version::DwgVersion;
    use crate::types::DxfVersion;

    #[test]
    fn test_table_content_r24_header_only() {
        let dwg = DwgVersion::AC24;
        let d = DxfVersion::AC1027;

        // Use separate stream writers for three-stream mode
        use crate::io::dwg::dwg_stream_writers::bit_writer::DwgBitWriter;
        use crate::io::dwg::dwg_stream_readers::bit_reader::DwgBitReader;

        let mut main = DwgBitWriter::new(dwg, d);
        let mut text = DwgBitWriter::new(dwg, d);
        let mut handle = DwgBitWriter::new(dwg, d);

        // ── AcDbLinkedData ──
        text.write_variable_text("");  // name
        text.write_variable_text("");  // description

        // ── AcDbLinkedTableData: columns ──
        main.write_bit_long(2);  // num_columns
        // Column 0
        text.write_variable_text("Col0");
        main.write_bit_long(0);  // custom data
        main.write_bit_long(0);  // cell style ID
        main.write_bit_double(5.0);  // column width
        // Column 1
        text.write_variable_text("Col1");
        main.write_bit_long(0);
        main.write_bit_long(0);
        main.write_bit_double(8.0);

        // ── AcDbLinkedTableData: rows ──
        main.write_bit_long(2);  // num_rows

        // Helper: write string value (value_type=String + text to text stream)
        let write_string_val = |m: &mut DwgBitWriter, t: &mut DwgBitWriter, s: &str| {
            m.write_bit_long(4);
            m.write_bit_long(0);
            m.write_bit_long(0);
            t.write_variable_text(s);
            t.write_variable_text("");
            t.write_variable_text(s);
        };

        // Row 0
        main.write_bit_long(2);  // cells_in_row
        // Cell 0,0
        main.write_bit_long(0);
        text.write_variable_text("");
        main.write_bit_long(0);
        main.write_bit_long(0);
        main.write_bit_long(1);
        main.write_bit_long(1);
        write_string_val(&mut main, &mut text, "R0C0_Text");
        // Cell 0,1
        main.write_bit_long(0);
        text.write_variable_text("");
        main.write_bit_long(0);
        main.write_bit_long(0);
        main.write_bit_long(1);
        main.write_bit_long(1);
        write_string_val(&mut main, &mut text, "R0C1_Text");
        // Row 0 cell style + height
        main.write_bit_long(0);
        main.write_bit_double(0.5);

        // Row 1
        main.write_bit_long(2);  // cells_in_row
        // Cell 1,0
        main.write_bit_long(0);
        text.write_variable_text("");
        main.write_bit_long(0);
        main.write_bit_long(0);
        main.write_bit_long(1);
        main.write_bit_long(1);
        write_string_val(&mut main, &mut text, "R1C0_Text");
        // Cell 1,1
        main.write_bit_long(0);
        text.write_variable_text("");
        main.write_bit_long(0);
        main.write_bit_long(0);
        main.write_bit_long(1);
        main.write_bit_long(1);
        write_string_val(&mut main, &mut text, "R1C1_Text");
        // Row 1 cell style + height
        main.write_bit_long(0);
        main.write_bit_double(0.5);

        // ── AcDbFormattedTableData (minimal) ──
        main.write_bit_long(0);
        main.write_bit_long(0);
        main.write_bit_long(0);
        main.write_bit_double(0.06);
        main.write_bit_double(0.06);
        main.write_bit(false);
        main.write_bit(false);

        // Row styles (3 iterations)
        for _ in 0..3 {
            handle.write_handle_undefined(0);
            main.write_bit_double(0.18);
            main.write_bit_short(1);
            main.write_cm_color(&crate::types::Color::ByBlock);
            main.write_cm_color(&crate::types::Color::ByBlock);
            main.write_bit(false);
            for _ in 0..6 {
                main.write_bit_short(0);
                main.write_bit(true);
                main.write_cm_color(&crate::types::Color::ByBlock);
            }
            main.write_bit_long(0);
            main.write_bit_long(0);
            text.write_variable_text("");
        }

        // ── Assemble readers ──
        let main_data = main.to_bytes();
        let text_data = text.to_bytes();
        let handle_data = handle.to_bytes();

        let main_reader = DwgBitReader::new(main_data, dwg, d);
        let text_reader = DwgBitReader::new(text_data, dwg, d);
        let handle_reader = DwgBitReader::new(handle_data, dwg, d);

        let mut r = DwgMergedReader::from_readers(
            main_reader,
            Some(text_reader),
            Some(handle_reader),
            d,
        );

        let result = read_table_content_r24(&mut r, dwg, d);
        assert_eq!(result.num_columns, 2);
        assert_eq!(result.num_rows, 2);
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0].cells.len(), 2);
        assert_eq!(result.rows[1].cells.len(), 2);

        // Verify cell text
        match &result.rows[0].cells[0].value {
            CellValue::String(s) => assert_eq!(s, "R0C0_Text"),
            other => panic!("Expected String, got {:?}", other),
        }
        match &result.rows[0].cells[1].value {
            CellValue::String(s) => assert_eq!(s, "R0C1_Text"),
            other => panic!("Expected String, got {:?}", other),
        }
        match &result.rows[1].cells[0].value {
            CellValue::String(s) => assert_eq!(s, "R1C0_Text"),
            other => panic!("Expected String, got {:?}", other),
        }
        match &result.rows[1].cells[1].value {
            CellValue::String(s) => assert_eq!(s, "R1C1_Text"),
            other => panic!("Expected String, got {:?}", other),
        }

        // Verify column widths
        assert!((result.column_widths[0] - 5.0).abs() < 0.001);
        assert!((result.column_widths[1] - 8.0).abs() < 0.001);
    }
}
