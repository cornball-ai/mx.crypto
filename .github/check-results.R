check_warnings <- function(lines, darwin = identical(Sys.info()[["sysname"]], "Darwin")) {
    status <- grep("^Status:", lines, value = TRUE)
    if (length(status) != 1L || any(grepl("ERROR", status, fixed = TRUE))) {
        stop("Missing or failed R CMD check result")
    }
    cat(status, "\n")
    headings <- grep("^\\* ", lines)
    bad <- grep("^\\* checking .* WARNING$", lines)
    if (grepl("WARNING", status, fixed = TRUE) && !length(bad)) {
        stop("Could not identify check warnings")
    }
    for (i in bad) {
        end <- min(c(headings[headings > i], length(lines) + 1L)) - 1L
        block <- trimws(lines[seq.int(i + 1L, end)])
        block <- block[nzchar(block)]
        bashisms <- identical(lines[i], "* checking top-level files ... WARNING") &&
            length(block) == 3L &&
            identical(block[1], "A complete check needs the 'checkbashisms' script.") &&
            grepl("^See section .*Configure and cleanup.*Writing R Extensions", block[2]) &&
            identical(block[3], "manual.")
        install <- grepl("^\\* checking whether package .* can be installed", lines[i])
        ld_warning <- "^ld: warning: building for macOS-[0-9.]+, but linking with dylib '.+' which was built for newer version [0-9.]+$"
        linker <- install && length(block) >= 3L &&
            identical(block[1], "Found the following significant warnings:") &&
            grepl("^See .*00install.out.* for details\\.$", tail(block, 1L)) &&
            all(grepl(ld_warning, block[seq.int(2L, length(block) - 1L)]))
        if (!darwin || !(bashisms || linker)) {
            stop(paste(c(lines[i], block), collapse = "\n"))
        }
        message("Known macOS runner warning retained: ", lines[i])
    }
    invisible(TRUE)
}

check_results <- function() {
    pkg <- "mx.crypto"
    check_dir <- normalizePath(paste0(pkg, ".Rcheck"), mustWork = TRUE)
    check_warnings(readLines(file.path(check_dir, "00check.log"), warn = FALSE))
    .libPaths(c(check_dir, .libPaths()))
    library(pkg, character.only = TRUE, lib.loc = check_dir)
    expected <- unname(read.dcf("DESCRIPTION")[1, "Version"])
    stopifnot(identical(as.character(utils::packageVersion(pkg)), expected))
    cat("Testing checked build:", find.package(pkg), expected, "\n")
    for (file in c("test_sas.R", "test_sas_commitment.R")) {
        result <- tinytest::run_test_file(file.path("inst", "tinytest", file),
            at_home = FALSE, verbose = 0, color = FALSE)
        print(result)
        if (!length(result) || !tinytest::all_pass(result)) {
            stop("SAS coverage failed or was skipped: ", file)
        }
    }
}

if (sys.nframe() == 0L) check_results()
