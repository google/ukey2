load("@rules_cc//cc:defs.bzl", "cc_proto_library")

licenses(["notice"])

proto_library(
    name = "proto",
    srcs = [
        "device_to_device_messages.proto",
        "securegcm.proto",
        "securemessage.proto",
        "ukey.proto",
    ],
)

cc_proto_library(
    name = "cc_proto",
    deps = [":proto"],
    visibility = ["//src:__subpackages__"],
)
