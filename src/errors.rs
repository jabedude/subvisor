error_chain::error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Nix(nix::Error);
        ParseInt(::std::num::ParseIntError);
        Parse(::std::string::ParseError);
    }

    //errors {
    //    InodeNotFound(t: String) {
    //        description("Inode not found")
    //        display("Inode not found: '{}'", t)
    //    }
    //}
}
