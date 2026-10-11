use std::fs;
use std::path::Path;

/// Leaf metadata does not reveal whether resolving its parents follows a symlink.
/// Reject redirected ancestry before validating or removing a planned path.
pub(crate) fn reject_symlink_ancestors(path: &Path) -> Result<(), String> {
    let absolute = std::path::absolute(path)
        .map_err(|error| format!("failed to resolve deletion path: {error}"))?;
    for ancestor in absolute.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
            format!("failed to inspect ancestor {}: {error}", ancestor.display())
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!("path ancestor {} is a symlink", ancestor.display()));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "path ancestor {} is not a directory",
                ancestor.display()
            ));
        }
    }
    Ok(())
}
