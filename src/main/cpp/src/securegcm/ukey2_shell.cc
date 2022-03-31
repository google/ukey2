// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The ukey2_shell binary is a command-line based wrapper, exercising the
// UKey2Handshake class. Its main use is to be run in a Java test, testing the
// compatibility of the Java and C++ implementations.
//
// This program can be run in two modes, initiator or responder (default is
// initiator):
//   ukey2_shell --mode=initiator --verification_string_length=32
//   ukey2_shell --mode=responder --verification_string_length=32
//
// In initiator mode, the program performs the initiator handshake, and in
// responder mode, it performs the responder handshake.
//
// After the handshake is done, the program establishes a secure connection and
// enters a loop in which it processes the following commands:
//    * encrypt <payload>: encrypts the payload and prints it.
//    * decrypt <message>: decrypts the message and prints the payload.
//    * session_unique:    prints the session unique value.
//
// IO is performed on stdin and stdout. To provide frame control, all frames
// will have the following simple format:
//   [ length | bytes ]
// where |length| is a 4 byte big-endian encoded unsigned integer.
#include <cassert>
#include <cstdio>
#include <iostream>
#include <memory>

#include <getopt.h>

#include "securegcm/ukey2_handshake.h"

#define LOG(ERROR) std::cerr
#define CHECK_EQ(a, b) do { if ((a) != (b)) abort(); } while(0)

namespace securegcm {

namespace {

// Writes |message| to stdout in the frame format.
void WriteFrame(const string& message) {
  // Write length of |message| in little-endian.
  const uint32_t length = message.length();
  fputc((length >> (3 * 8)) & 0xFF, stdout);
  fputc((length >> (2 * 8)) & 0xFF, stdout);
  fputc((length >> (1 * 8)) & 0xFF, stdout);
  fputc((length >> (0 * 8)) & 0xFF, stdout);

  // Write message to stdout.
  CHECK_EQ(message.length(),
           fwrite(message.c_str(), 1, message.length(), stdout));
  CHECK_EQ(0, fflush(stdout));
}

// Returns a message read from stdin after parsing it from the frame format.
string ReadFrame() {
  // Read length of the frame from the stream.
  uint8_t length_data[sizeof(uint32_t)];
  CHECK_EQ(sizeof(uint32_t), fread(&length_data, 1, sizeof(uint32_t), stdin));

  uint32_t length = 0;
  length |= static_cast<uint32_t>(length_data[0]) << (3 * 8);
  length |= static_cast<uint32_t>(length_data[1]) << (2 * 8);
  length |= static_cast<uint32_t>(length_data[2]) << (1 * 8);
  length |= static_cast<uint32_t>(length_data[3]) << (0 * 8);

  // Read |length| bytes from the stream.
  std::unique_ptr<char[]> buffer(new char[length]);
  CHECK_EQ(length, fread(buffer.get(), 1, length, stdin));

  return string(buffer.get(), length);
}

}  // namespace

// Handles the runtime of the program in initiator or responder mode.
class UKey2Shell {
 public:
  explicit UKey2Shell(int verification_string_length);
  ~UKey2Shell();

  // Runs the shell, performing the initiator handshake for authentication.
  bool RunAsInitiator();

  // Runs the shell, performing the responder handshake for authentication.
  bool RunAsResponder();

 private:
  // Writes the next handshake message obtained from |ukey2_handshake_| to
  // stdout.
  // If an error occurs, |tag| is logged.
  bool WriteNextHandshakeMessage(const string& tag);

  // Reads the next handshake message from stdin and parses it using
  // |ukey2_handshake_|.
  // If an error occurs, |tag| is logged.
  bool ReadNextHandshakeMessage(const string& tag);

  // Writes the verification string to stdout and waits for a confirmation from
  // stdin.
  bool ConfirmVerificationString();

  // After authentication is completed, this function runs the loop handing the
  // secure connection.
  bool RunSecureConnectionLoop();

  std::unique_ptr<UKey2Handshake> ukey2_handshake_;
  const int verification_string_length_;
};

UKey2Shell::UKey2Shell(int verification_string_length)
    : verification_string_length_(verification_string_length) {}

UKey2Shell::~UKey2Shell() {}

bool UKey2Shell::WriteNextHandshakeMessage(const string& tag) {
  const std::unique_ptr<string> message =
      ukey2_handshake_->GetNextHandshakeMessage();
  if (!message) {
    LOG(ERROR) << "Failed to create [" << tag
               << "] message: " << ukey2_handshake_->GetLastError();
    return false;
  }
  WriteFrame(*message);
  return true;
}

bool UKey2Shell::ReadNextHandshakeMessage(const string& tag) {
  const string message = ReadFrame();
  const UKey2Handshake::ParseResult result =
      ukey2_handshake_->ParseHandshakeMessage(message);
  if (!result.success) {
    LOG(ERROR) << "Failed to parse [" << tag
               << "] message: " << ukey2_handshake_->GetLastError();
    if (result.alert_to_send) {
      WriteFrame(*result.alert_to_send);
    }
    return false;
  }
  return true;
}

bool UKey2Shell::ConfirmVerificationString() {
  const std::unique_ptr<string> auth_string =
      ukey2_handshake_->GetVerificationString(verification_string_length_);
  if (!auth_string) {
    LOG(ERROR) << "Failed to get verification string: "
               << ukey2_handshake_->GetLastError();
    return false;
  }
  WriteFrame(*auth_string);

  // Wait for ack message.
  const string message = ReadFrame();
  if (message != "ok") {
    LOG(ERROR) << "Expected string 'ok'";
    return false;
  }
  ukey2_handshake_->VerifyHandshake();
  return true;
}

bool UKey2Shell::RunSecureConnectionLoop() {
  const std::unique_ptr<D2DConnectionContextV1> connection_context =
      ukey2_handshake_->ToConnectionContext();
  if (!connection_context) {
    LOG(ERROR) << "Failed to create connection context: "
               << ukey2_handshake_->GetLastError();
    return false;
  }

  for (;;) {
    // Parse the next expression.
    const string expression = ReadFrame();
    const size_t pos = expression.find(" ");
    if (pos == std::string::npos) {
      LOG(ERROR) << "Invalid command in connection loop.";
      return false;
    }
    const string command = expression.substr(0, pos);

    if (command == "encrypt") {
      const string payload = expression.substr(pos + 1, expression.length());
      std::unique_ptr<string> encoded_message =
          connection_context->EncodeMessageToPeer(payload);
      if (!encoded_message) {
        LOG(ERROR) << "Failed to encode payload of size " << payload.length();
        return false;
      }
      WriteFrame(*encoded_message);
    } else if (command == "decrypt") {
      const string message = expression.substr(pos + 1, expression.length());
      std::unique_ptr<string> decoded_payload =
          connection_context->DecodeMessageFromPeer(message);
      if (!decoded_payload) {
        LOG(ERROR) << "Failed to decode message of size " << message.length();
        return false;
      }
      WriteFrame(*decoded_payload);
    } else if (command == "session_unique") {
      std::unique_ptr<string> session_unique =
          connection_context->GetSessionUnique();
      if (!session_unique) {
        LOG(ERROR) << "Failed to get session unique.";
        return false;
      }
      WriteFrame(*session_unique);
    } else {
      LOG(ERROR) << "Unrecognized command: " << command;
      return false;
    }
  }
}

bool UKey2Shell::RunAsInitiator() {
  ukey2_handshake_ = UKey2Handshake::ForInitiator(
      UKey2Handshake::HandshakeCipher::P256_SHA512);
  if (!ukey2_handshake_) {
    LOG(ERROR) << "Unable to create UKey2Handshake";
    return false;
  }

  // Perform handshake.
  if (!WriteNextHandshakeMessage("Initiator Init")) return false;
  if (!ReadNextHandshakeMessage("Responder Init")) return false;
  if (!WriteNextHandshakeMessage("Initiator Finish")) return false;
  if (!ConfirmVerificationString()) return false;

  // Create a connection context.
  return RunSecureConnectionLoop();
}

bool UKey2Shell::RunAsResponder() {
  ukey2_handshake_ = UKey2Handshake::ForResponder(
      UKey2Handshake::HandshakeCipher::P256_SHA512);
  if (!ukey2_handshake_) {
    LOG(ERROR) << "Unable to create UKey2Handshake";
    return false;
  }

  // Perform handshake.
  if (!ReadNextHandshakeMessage("Initiator Init")) return false;
  if (!WriteNextHandshakeMessage("Responder Init")) return false;
  if (!ReadNextHandshakeMessage("Initiator Finish")) return false;
  if (!ConfirmVerificationString()) return false;

  // Create a connection context.
  return RunSecureConnectionLoop();
}

}  // namespace securegcm

static void printUsage(char* name) {
  std::string exec_name(name);
  std::string usage(

      "ICACHE is a command-line based wrapper, exercising the\n"
      "UKey2Handshake class. Its main use is to be run in a Java test, testing the\n"
      "compatibility of the Java and C++ implementations.\n"
      "\n"
      "This program can be run in two modes, initiator or responder (default is\n"
      "initiator):\n"
      "  ukey2_shell --mode=initiator --verification_string_length=32\n"
      "  ukey2_shell --mode=responder --verification_string_length=32\n"
      );
  const std::string from("ICACHE");
  for (size_t pos = usage.find(from); pos != std::string::npos; pos = usage.find(from, pos)) {
    usage.replace(pos, from.length(), exec_name);
  }
  printf("%s", usage.c_str());
}

int main(int argc, char** argv) {
  static constexpr const char* OPTSTR = "ha:";
  static const struct option OPTIONS[] = {
      { "help",                       no_argument, 0, 'h' },
      { "mode",                       required_argument, 0, 'm' },
      { "verification_string_length", required_argument, 0, 'l' },
      { 0, 0, 0, 0 }  // termination of the option list
  };
  int opt;
  int option_index = 0;
  int verification_string_length = 32;
  string mode = "initiator";

  while ((opt = getopt_long(argc, argv, OPTSTR, OPTIONS, &option_index)) >= 0) {
    switch (opt) {
      default:
      case 'h':
        printUsage(argv[0]);
        return 0;
      case 'l':
        verification_string_length = atoi(optarg);
        break;
      case 'm':
        mode = optarg;
        break;
    }
  }

  if (verification_string_length < 1 || verification_string_length > 32) {
    LOG(ERROR) << "Invalid flag value, verification_string_length: "
               << verification_string_length;
    return 1;
  }

  securegcm::UKey2Shell shell(verification_string_length);
  int exit_code = 0;
  if (mode == "initiator") {
    exit_code = !shell.RunAsInitiator();
  } else if (mode == "responder") {
    exit_code = !shell.RunAsResponder();
  } else {
    LOG(ERROR) << "Invalid flag value, mode: " << mode;
    exit_code = 1;
  }
  return exit_code;
}
