fn main() {
    // Only compile resources on Windows
    #[cfg(windows)]
    {
        embed_resource::compile("cllxfs-gui.rc", embed_resource::NONE);
    }
}
