// write_record.rs — seal an account with the Rust side, so the browser's
// vault.js can be asked whether it opens.
//
//   cargo run -p bitmule-account --example write_record -- <out.json> <password>

use bitmule_account as account;

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().expect("usage: write_record <out.json> <password>");
    let password = args.next().expect("usage: write_record <out.json> <password>");
    let (mut record, mut acct) = account::create("native", &password, Some("extended")).unwrap();
    acct.account_id = Some("acct_native".into());
    account::seal_into(&mut record, &password, &acct).unwrap();
    std::fs::write(&out, serde_json::to_string_pretty(&record).unwrap() + "\n").unwrap();
    println!("{out}: pub {}", record.public_key);
    println!("account_id acct_native, plan {}", record.plan());
}
