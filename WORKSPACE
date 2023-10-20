load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-3.24.4",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.24.4.tar.gz"],
)

http_archive(
    name = "com_google_protobuf_cc",
    strip_prefix = "protobuf-3.24.4",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.24.4.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
# Load common dependencies.
protobuf_deps()

http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-main",
    urls = ["https://github.com/google/googletest/archive/main.zip"],
)

http_archive(
    name = "com_google_absl",
    strip_prefix = "abseil-cpp-master",
    urls = ["https://github.com/abseil/abseil-cpp/archive/master.zip"],
)

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "boringssl",
    branch = "master-with-bazel",
    remote = "https://boringssl.googlesource.com/boringssl",
)
