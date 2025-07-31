use crate::cert::CertificateColumn;
use std::fmt::Display;
use std::io::{self, Write};

/// Handle broken pipe errors gracefully (e.g., when piping to head)
fn print_line(line: &str) {
    if let Err(e) = writeln!(io::stdout(), "{line}") {
        if e.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
    }
}

/// Trait for types that can provide column values
pub trait GetColumnValue {
    fn get_column_value(&self, column: &CertificateColumn) -> String;
}

/// Output format configuration
#[derive(Clone, Debug)]
pub struct OutputFormat {
    pub raw: bool,
}

/// Build table data from certificates and columns
pub fn build_table_data<T>(
    certificates: &[T],
    parsed_columns: &[CertificateColumn],
) -> Vec<Vec<String>>
where
    T: GetColumnValue,
{
    certificates
        .iter()
        .map(|cert| {
            parsed_columns
                .iter()
                .map(|col| cert.get_column_value(col))
                .collect()
        })
        .collect()
}

/// Build table data with headers from certificates and columns
pub fn build_table_data_with_headers<T>(
    certificates: &[T],
    parsed_columns: &[CertificateColumn],
) -> (Vec<String>, Vec<Vec<String>>)
where
    T: GetColumnValue,
{
    let headers = parsed_columns
        .iter()
        .map(|col| col.header().to_string())
        .collect();

    let data = build_table_data(certificates, parsed_columns);

    (headers, data)
}

impl OutputFormat {
    pub fn new(raw: bool) -> Self {
        Self { raw }
    }

    /// Print tabular data - either raw (tab-separated) or formatted (column-aligned)
    pub fn print_table<T>(&self, data: &[Vec<T>])
    where
        T: Display + AsRef<str>,
    {
        if data.is_empty() {
            return;
        }

        if self.raw {
            // Raw output: tab-separated values
            for row in data {
                let line = row
                    .iter()
                    .map(|cell| cell.as_ref())
                    .collect::<Vec<_>>()
                    .join("\t");
                print_line(&line);
            }
        } else {
            // Formatted output: column-aligned like `column -t`
            self.print_formatted_table(data);
        }
    }

    /// Print tabular data with headers - either raw (tab-separated) or formatted (column-aligned)
    pub fn print_table_with_headers<T>(&self, headers: &[String], data: &[Vec<T>])
    where
        T: Display + AsRef<str>,
    {
        if self.raw {
            // Raw output: tab-separated values (no headers in raw mode)
            for row in data {
                let line = row
                    .iter()
                    .map(|cell| cell.as_ref())
                    .collect::<Vec<_>>()
                    .join("\t");
                print_line(&line);
            }
        } else {
            // Formatted output: include headers
            if !headers.is_empty() {
                let mut all_data = vec![headers.iter().map(|h| h.as_str()).collect()];
                all_data.extend(
                    data.iter()
                        .map(|row| row.iter().map(|cell| cell.as_ref()).collect()),
                );
                self.print_formatted_table(&all_data);
            } else if !data.is_empty() {
                self.print_formatted_table(data);
            }
        }
    }

    /// Print single-column data
    pub fn print_list<T>(&self, items: &[T])
    where
        T: Display,
    {
        for item in items {
            print_line(&item.to_string());
        }
    }

    /// Print key-value pairs
    pub fn print_key_value<K, V>(&self, pairs: &[(K, V)])
    where
        K: Display + AsRef<str>,
        V: Display + AsRef<str>,
    {
        let data: Vec<Vec<String>> = pairs
            .iter()
            .map(|(k, v)| vec![k.to_string(), v.to_string()])
            .collect();

        self.print_table(&data);
    }

    fn print_formatted_table<T>(&self, data: &[Vec<T>])
    where
        T: Display + AsRef<str>,
    {
        if data.is_empty() {
            return;
        }

        // Calculate column widths
        let num_cols = data[0].len();
        let mut col_widths = vec![0; num_cols];

        for row in data {
            for (i, cell) in row.iter().enumerate() {
                col_widths[i] = col_widths[i].max(cell.as_ref().len());
            }
        }

        // Print formatted rows
        for row in data {
            let formatted_cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    if i == row.len() - 1 {
                        // Last column - no padding needed
                        cell.to_string()
                    } else {
                        // Pad to column width
                        format!("{:<width$}", cell.as_ref(), width = col_widths[i])
                    }
                })
                .collect();

            print_line(&formatted_cells.join("  "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_output() {
        let format = OutputFormat::new(true);
        let data = vec![
            vec!["short", "medium", "very_long_column"],
            vec!["a", "bb", "ccc"],
        ];

        // This would print:
        // short\tmedium\tvery_long_column
        // a\tbb\tccc
        format.print_table(&data);
    }

    #[test]
    fn test_formatted_output() {
        let format = OutputFormat::new(false);
        let data = vec![
            vec!["short", "medium", "very_long_column"],
            vec!["a", "bb", "ccc"],
        ];

        // This would print:
        // short  medium  very_long_column
        // a      bb      ccc
        format.print_table(&data);
    }
}
