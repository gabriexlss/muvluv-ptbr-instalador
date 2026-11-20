pub const TRANSLATION_REPO_OWNER: &str = "gabriexlss";
pub const TRANSLATION_REPO_NAME: &str = "muvluv-ptbr-traducao";
pub const TRANSLATION_ZIP_ASSET: &str = "muvluv-ptbr-translation.zip";
pub const TRANSLATION_ZIP_SHA256_ASSET: &str = "muvluv-ptbr-translation.zip.sha256";
pub const RECOMMENDED_FREE_SPACE_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

pub fn latest_zip_url() -> String {
    format!(
        "https://github.com/{}/{}/releases/latest/download/{}",
        TRANSLATION_REPO_OWNER, TRANSLATION_REPO_NAME, TRANSLATION_ZIP_ASSET
    )
}

pub fn latest_zip_sha256_url() -> String {
    format!(
        "https://github.com/{}/{}/releases/latest/download/{}",
        TRANSLATION_REPO_OWNER, TRANSLATION_REPO_NAME, TRANSLATION_ZIP_SHA256_ASSET
    )
}

pub fn latest_release_api_url() -> String {
    format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        TRANSLATION_REPO_OWNER, TRANSLATION_REPO_NAME
    )
}

pub fn repo_web_url() -> String {
    format!(
        "https://github.com/{}/{}",
        TRANSLATION_REPO_OWNER, TRANSLATION_REPO_NAME
    )
}
