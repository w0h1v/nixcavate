//! `list`: every artifact, its OS, its category and the paths it reads.

use clap::Args;
use nixcavate_artifacts::artifacts;
use serde::Serialize;

#[derive(Args)]
pub struct ListArgs {
    /// Print JSON instead of a table
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Row {
    id: &'static str,
    os: Vec<&'static str>,
    category: &'static str,
    description: &'static str,
    paths: &'static [&'static str],
}

pub fn run(args: &ListArgs) -> Result<u8, String> {
    let rows: Vec<Row> = artifacts()
        .map(|a| Row {
            id: a.id,
            os: a.os.iter().map(|os| os.as_str()).collect(),
            category: a.category.as_str(),
            description: a.description,
            paths: a.paths,
        })
        .collect();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?);
        return Ok(crate::EXIT_OK);
    }
    let width = |f: fn(&Row) -> usize, title: &str| rows.iter().map(f).max().unwrap_or(0).max(title.len());
    let (id_w, os_w, cat_w) = (
        width(|r| r.id.len(), "ARTIFACT"),
        width(|r| r.os.join(",").len(), "OS"),
        width(|r| r.category.len(), "CATEGORY"),
    );
    println!("{:id_w$}  {:os_w$}  {:cat_w$}  DESCRIPTION / PATHS", "ARTIFACT", "OS", "CATEGORY");
    for row in &rows {
        println!("{:id_w$}  {:os_w$}  {:cat_w$}  {}", row.id, row.os.join(","), row.category, row.description);
        for path in row.paths {
            println!("{:id_w$}  {:os_w$}  {:cat_w$}    {path}", "", "", "");
        }
    }
    println!("\n{} artifacts", rows.len());
    Ok(crate::EXIT_OK)
}
