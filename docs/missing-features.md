@Kenna
after implementing a feature, add it to features.md and remove it here

## Multi-file sending
if multiple files or a directory is selected, zip it (without compression, since we compress later via zstd).
add a flag to the metadata so the reciever knows that multiple files and not a zip-file was sent.

- In the cli and native apps, unpack as if multiple files where recieved.
- in the web interface ask the user if they want to zip of everything or individual files (if supported)
