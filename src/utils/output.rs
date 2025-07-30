use crate::cert::CertificateColumn;
use std::fmt::Display;

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
                println!("{line}");
            }
        } else {
            // Formatted output: column-aligned like `column -t`
            self.print_formatted_table(data);
        }
    }

    /// Print single-column data
    pub fn print_list<T>(&self, items: &[T])
    where
        T: Display,
    {
        for item in items {
            println!("{item}");
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

            println!("{}", formatted_cells.join("  "));
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
