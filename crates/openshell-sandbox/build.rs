// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build script for openshell-sandbox.
//!
//! On aarch64-linux (DPU ARM) with DOCA present, compiles the doca_cc_server.c
//! wrapper and links it (plus libdoca_comch) into the openshell-dpu-proxy binary.
//!
//! On other targets (x86 dev machines, CI) the DOCA headers/libs are absent.
//! In that case we emit a stub object so the Rust code still compiles — the
//! comch transport will not be functional, but the TCP mode still works.

fn main() {
    let doca_include = "/opt/mellanox/doca/include";
    let doca_lib = "/opt/mellanox/doca/lib/aarch64-linux-gnu";
    let cc_wrapper_src = "../../openshell-bluefield/dpu/proxy/doca_cc_server.c";
    let cc_wrapper_hdr = "../../openshell-bluefield/dpu/proxy/doca_cc_server.h";

    // Only attempt the DOCA build if the headers exist (i.e. we're on the DPU ARM).
    let has_doca = std::path::Path::new(doca_include).join("doca_comch.h").exists();
    let has_cc_wrapper = std::path::Path::new(cc_wrapper_src).exists()
        && std::path::Path::new(cc_wrapper_hdr).exists();

    // Rerun if the C source changes.
    println!("cargo:rerun-if-changed={cc_wrapper_src}");
    println!("cargo:rerun-if-changed={cc_wrapper_hdr}");

    if has_doca && has_cc_wrapper {
        // Full build: compile the real C wrapper and link DOCA.
        cc::Build::new()
            .file(cc_wrapper_src)
            .include(doca_include)
            .flag("-pthread")
            .compile("doca_cc_server");

        // DOCA 3.3.0 library structure:
        //   libdoca_comch  — Comm Channel tasks, server/client API
        //   libdoca_common — doca_task_free, doca_pe_*, doca_dev_* etc.
        println!("cargo:rustc-link-lib=doca_comch");
        println!("cargo:rustc-link-lib=doca_common");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-search=native={doca_lib}");
    } else {
        if has_doca && !has_cc_wrapper {
            println!(
                "cargo:warning=DOCA headers are present but Comm Channel wrapper sources are missing; building comch stub so TCP mode remains available"
            );
        }
        // Stub build: emit a minimal object that satisfies the linker on non-DPU hosts.
        // The cc_server_* symbols are defined as no-ops / null returns so the crate
        // compiles, but the comch transport will not function at runtime.
        let stub_src = r#"
#include <stdint.h>
#include <stdlib.h>

typedef void cc_server_t;
typedef void (*cc_msg_cb_t)(uint64_t, const uint8_t *, uint32_t, void *);
typedef void (*cc_conn_cb_t)(uint64_t, void *);

cc_server_t *cc_server_create(const char *pci, const char *rep_pci,
                               const char *svc,
                               cc_msg_cb_t msg, cc_conn_cb_t conn,
                               cc_conn_cb_t disconn, void *ud)
{
    (void)pci; (void)rep_pci; (void)svc;
    (void)msg; (void)conn; (void)disconn; (void)ud;
    return NULL;
}
int  cc_server_send(cc_server_t *s, uint64_t cid, const uint8_t *b, uint32_t l)
    { (void)s; (void)cid; (void)b; (void)l; return -1; }
void cc_server_run(cc_server_t *s)     { (void)s; }
void cc_server_stop(cc_server_t *s)    { (void)s; }
void cc_server_destroy(cc_server_t *s) { (void)s; }
"#;

        let out_dir = std::env::var("OUT_DIR").unwrap();
        let stub_path = std::path::Path::new(&out_dir).join("doca_cc_server_stub.c");
        std::fs::write(&stub_path, stub_src).expect("write stub");

        cc::Build::new()
            .file(&stub_path)
            .compile("doca_cc_server");
    }
}
