#include "backend/session/SessionStore.h"
#include "TestSupport.h"

#include <barrier>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
using namespace debugger;

using debugger::test::require;

template <typename Action>
void require_error(Action action, const char *message) {
  try {
    action();
  } catch (const std::runtime_error &) {
    return;
  }
  throw std::runtime_error(message);
}

class TemporaryDirectory {
public:
  TemporaryDirectory() {
    auto pattern =
        (std::filesystem::temp_directory_path() / "mydbg-session-test-XXXXXX")
            .string();
    if (!::mkdtemp(pattern.data()))
      throw std::runtime_error("mkdtemp failed");
    path = pattern;
  }
  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
  std::filesystem::path path;
};

void put(const std::filesystem::path &path, const std::string &bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.exceptions(std::ios::badbit | std::ios::failbit);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  stream.close();
}

std::string get(const std::filesystem::path &path) {
  std::ifstream stream(path, std::ios::binary);
  require(static_cast<bool>(stream), "test fixture must be readable");
  return {std::istreambuf_iterator<char>(stream),
          std::istreambuf_iterator<char>()};
}

std::string replace(std::string value, const std::string &before,
                    const std::string &after) {
  const auto at = value.find(before);
  require(at != std::string::npos, "corruption fixture field must exist");
  value.replace(at, before.size(), after);
  return value;
}

struct Fixture {
  TemporaryDirectory temporary;
  std::filesystem::path binary = temporary.path / "program";
  std::filesystem::path directory = temporary.path / "sessions";
  std::string sha;
  Fixture() {
    put(binary, "abc");
    sha = SessionStore::hash_file(binary);
  }
  std::filesystem::path document() const { return directory / (sha + ".json"); }
};

SessionAnalysisEdit rename_edit(std::string from, std::string to) {
  return {SavedAnalysisKind::Rename,
          SavedSymbolKind::Local,
          0x20000000000001ULL,
          std::move(from),
          std::numeric_limits<std::uint64_t>::max(),
          true,
          std::move(to)};
}

void hash_and_content_identity() {
  Fixture fixture;
  require(
      fixture.sha ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "SHA-256 must match the standard abc vector");
  const auto empty = fixture.temporary.path / "empty";
  put(empty, "");
  require(
      SessionStore::hash_file(empty) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "the empty-file SHA-256 digest must be finalized");
  const auto streamed = fixture.temporary.path / "streamed";
  put(streamed, std::string(1000000, 'a'));
  require(
      SessionStore::hash_file(streamed) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
      "streaming across multiple buffers must match the million-a SHA-256 "
      "vector");
  SessionStore store(fixture.directory);
  const auto original = store.load(fixture.sha, fixture.binary.string());
  SessionDebuggerState debugger;
  debugger.watches = {"counter + 1"};
  store.save_debugger(original.identity, debugger);

  const auto moved = fixture.temporary.path / "moved-program";
  std::filesystem::rename(fixture.binary, moved);
  const auto copied = fixture.temporary.path / "copied-program";
  std::filesystem::copy_file(moved, copied);
  require(SessionStore::hash_file(moved) == fixture.sha &&
              SessionStore::hash_file(copied) == fixture.sha,
          "moved and copied bytes must share the same key");
  SessionStore reopened(fixture.directory);
  const auto relocated =
      reopened.load(SessionStore::hash_file(copied), copied.string());
  require(relocated.identity == original.identity &&
              relocated.debugger.watches == debugger.watches &&
              relocated.binary_path == fixture.binary.string(),
          "relocation must preserve the native records' old locator until "
          "rewritten");
  reopened.save_debugger(relocated.identity, relocated.debugger);
  const auto rewritten = store.load(fixture.sha, moved.string());
  require(
      rewritten.binary_path == copied.string(),
      "saving rewritten debugger records must advance their locator together");
  put(copied, "abd");
  const auto different_hash = SessionStore::hash_file(copied);
  require(different_hash != fixture.sha, "changed bytes need a different key");
  const auto different = reopened.load(different_hash, copied.string());
  require(different.debugger.watches.empty(),
          "a reused pathname must not inherit intent from different contents");
}

void exact_addresses_unicode_and_order() {
  Fixture fixture;
  SessionStore store(fixture.directory);
  const auto initial = store.load(fixture.sha, fixture.binary.string());
  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  const SessionAddress address{fixture.sha, fixture.binary.string(), maximum};
  SessionDebuggerState debugger;
  debugger.breakpoints = {{"{\"resolver\":\"名前\"}", "rax == 7", "", ""}};
  debugger.watches = {"résultat + \"値\""};
  debugger.symbols = {{"入口𐐷", address}};
  debugger.arguments = {"", "one two", "\"三\""};
  debugger.working_directory = "/tmp/作業";
  const auto debug_status = store.save_debugger(initial.identity, debugger);
  require(debug_status.analysis_revision == initial.analysis_revision,
          "debugger intent must not invalidate analysis journals");
  const auto first = rename_edit("原名", "中間");
  auto second = first;
  second.kind = SavedAnalysisKind::SetType;
  second.target_name = "中間";
  second.value = "unsigned long long";
  const auto third = rename_edit("中間", "最終");
  for (const auto &edit : {first, second, third})
    store.append_analysis(initial.identity, fixture.sha,
                          fixture.binary.string(), edit);
  store.set_comment(initial.identity, address, "old comment");
  auto relocated_address = address;
  relocated_address.module_path = "/elsewhere/program";
  const std::string comment = "説明𐐷\n\"quoted\" \\ tab\t終";
  store.set_comment(initial.identity, relocated_address, comment);
  store.set_comment(initial.identity,
                    {fixture.sha, fixture.binary.string(), 0x20000000000001ULL},
                    "neighbor");

  SessionStore reopened(fixture.directory);
  const auto saved = reopened.load(fixture.sha, fixture.binary.string());
  require(
      saved.debugger.symbols.at(0).address.file_address == maximum &&
          saved.debugger.symbols.at(0).name == "入口𐐷" &&
          saved.debugger.watches == debugger.watches &&
          saved.debugger.arguments == debugger.arguments &&
          saved.debugger.working_directory == debugger.working_directory &&
          saved.debugger.breakpoints.at(0).serialized ==
              debugger.breakpoints.at(0).serialized,
      "wide unsigned addresses and authored Unicode must round-trip exactly");
  const auto &edits = saved.analysis.at(0).edits;
  require(edits.size() == 3 && edits[0].target_name == "原名" &&
              edits[0].value == "中間" &&
              edits[1].kind == SavedAnalysisKind::SetType &&
              edits[1].target_name == "中間" &&
              edits[1].value == "unsigned long long" &&
              edits[2].target_name == "中間" && edits[2].value == "最終" &&
              edits[2].function_file_address == 0x20000000000001ULL &&
              edits[2].has_target_file_address &&
              edits[2].target_file_address == maximum,
          "ordered dependent rename/type edits must not compact or round "
          "addresses");
  require(
      saved.comments.size() == 2 &&
          saved.comments[0].address.file_address == maximum &&
          saved.comments[0].text == comment &&
          saved.comments[0].address.module_path ==
              relocated_address.module_path,
      "comment upserts use module contents plus exact address, never locator");
  const auto before_delete = reopened.status(fixture.sha);
  const auto after_delete = reopened.set_comment(saved.identity, address, "");
  const auto deleted = store.load(fixture.sha, fixture.binary.string());
  require(
      deleted.comments.size() == 1 && deleted.comments[0].text == "neighbor" &&
          after_delete.analysis_revision == before_delete.analysis_revision + 1,
      "empty comments delete just their address and invalidate provider "
      "annotations");
}

void independent_store_merging() {
  Fixture fixture;
  SessionStore debugger_store(fixture.directory);
  SessionStore analysis_store(fixture.directory);
  SessionStore comment_store(fixture.directory);
  const auto identity =
      debugger_store.load(fixture.sha, fixture.binary.string()).identity;
  analysis_store.load(fixture.sha, fixture.binary.string());
  comment_store.load(fixture.sha, fixture.binary.string());
  std::barrier start(3);
  std::exception_ptr failures[3];
  constexpr int count = 12;
  std::jthread debugger([&] {
    start.arrive_and_wait();
    try {
      for (int i = 0; i < count; ++i) {
        SessionDebuggerState state;
        state.watches = {"expression_" + std::to_string(i)};
        debugger_store.save_debugger(identity, state);
      }
    } catch (...) {
      failures[0] = std::current_exception();
    }
  });
  std::jthread analysis([&] {
    start.arrive_and_wait();
    try {
      for (int i = 0; i < count; ++i)
        analysis_store.append_analysis(
            identity, fixture.sha, fixture.binary.string(),
            rename_edit("name_" + std::to_string(i),
                        "name_" + std::to_string(i + 1)));
    } catch (...) {
      failures[1] = std::current_exception();
    }
  });
  std::jthread comments([&] {
    start.arrive_and_wait();
    try {
      for (int i = 0; i < count; ++i)
        comment_store.set_comment(identity,
                                  {fixture.sha, fixture.binary.string(),
                                   static_cast<std::uint64_t>(i)},
                                  "comment_" + std::to_string(i));
    } catch (...) {
      failures[2] = std::current_exception();
    }
  });
  debugger.join();
  analysis.join();
  comments.join();
  for (const auto &failure : failures)
    if (failure)
      std::rethrow_exception(failure);
  const auto saved = debugger_store.load(fixture.sha, fixture.binary.string());
  require(
      saved.debugger.watches == std::vector<std::string>{"expression_11"} &&
          saved.analysis.size() == 1 &&
          saved.analysis[0].edits.size() == count &&
          saved.comments.size() == count,
      "independently cached concurrent stores must merge all three sections");
  for (int i = 0; i < count; ++i)
    require(
        saved.analysis[0].edits[i].target_name == "name_" + std::to_string(i) &&
            saved.analysis[0].edits[i].value == "name_" + std::to_string(i + 1),
        "concurrent unrelated saves must preserve journal application order");
  require(saved.revision == 3 * count && saved.analysis_revision == 2 * count,
          "each locked update must advance the right revisions without lost "
          "writes");
}

void clear_fences_stale_writes() {
  Fixture fixture;
  SessionStore active(fixture.directory);
  SessionStore stale(fixture.directory);
  const auto before = active.load(fixture.sha, fixture.binary.string());
  stale.load(fixture.sha, fixture.binary.string());
  SessionDebuggerState debugger;
  debugger.watches = {"must_not_return"};
  active.save_debugger(before.identity, debugger);
  active.append_analysis(before.identity, fixture.sha, fixture.binary.string(),
                         rename_edit("a", "b"));
  const SessionAddress address{fixture.sha, fixture.binary.string(), 0x1234};
  active.set_comment(before.identity, address, "must also disappear");
  const auto cleared = active.clear(fixture.sha);
  require(
      cleared.identity.sha256 == before.identity.sha256 &&
          cleared.identity.epoch != before.identity.epoch &&
          cleared.debugger.watches.empty() && cleared.analysis.empty() &&
          cleared.comments.empty(),
      "clear must replace all authored sections with a new-epoch tombstone");
  require_error([&] { stale.save_debugger(before.identity, debugger); },
                "old debugger work must not resurrect cleared state");
  require_error(
      [&] {
        stale.append_analysis(before.identity, fixture.sha,
                              fixture.binary.string(), rename_edit("a", "b"));
      },
      "old decompiler work must not resurrect cleared state");
  require_error([&] { stale.set_comment(before.identity, address, "stale"); },
                "old comments must not resurrect cleared state");
  require_error([&] { active.read(before.identity); },
                "cached reads must reject an obsolete epoch");
  require(!stale.status(fixture.sha).error.empty(),
          "failed stale writes must remain visible in cached status");
  SessionStore restarted(fixture.directory);
  const auto tombstone = restarted.load(fixture.sha, fixture.binary.string());
  require(tombstone.identity == cleared.identity &&
              tombstone.debugger.watches.empty() &&
              tombstone.analysis.empty() && tombstone.comments.empty(),
          "the empty epoch fence must survive process restart");
  const auto recovered = stale.load(fixture.sha, fixture.binary.string());
  const auto status =
      stale.set_comment(recovered.identity, address, "new epoch");
  require(
      status.error.empty() && status.writable && status.comment_count == 1,
      "an explicit reload permits new-epoch writes and clears the old error");
}

void malformed_version_and_explicit_clear() {
  Fixture fixture;
  SessionStore store(fixture.directory);
  auto current = store.load(fixture.sha, fixture.binary.string());
  const auto good = get(fixture.document());
  std::vector<std::string> corruptions{
      "{\"version\":",
      replace(good, "\"version\":1", "\"version\":2"),
      replace(good, "\"sha256\":\"" + fixture.sha,
              "\"sha256\":\"" + std::string(64, '0')),
      good + " false",
      replace(good, "\"revision\":0", "\"revision\":-1"),
      replace(good, "\"revision\":0", "\"revision\":18446744073709551616"),
      replace(good, "\"revision\":0", "\"revision\":0.5"),
      replace(good, "\"epoch\":\"", "\"epoch\":\"\\u0000"),
      replace(good, "\"version\":1", "\"version\":1,\"version\":1"),
      std::string(65, '[') + "0" + std::string(65, ']')};
  for (const auto &corrupt : corruptions) {
    put(fixture.document(), corrupt);
    require_error(
        [&] { store.load(fixture.sha, fixture.binary.string()); },
        "malformed, unsupported, or mismatched documents must be rejected");
    const auto status = store.status(fixture.sha);
    require(!status.writable && !status.error.empty() &&
                status.identity.sha256 == fixture.sha &&
                status.identity.epoch.empty(),
            "a load failure must expose its hash and error without a "
            "replayable epoch");
    require_error([&] { store.save_debugger(current.identity, {}); },
                  "a mutation must not replace rejected on-disk input");
    require(get(fixture.document()) == corrupt,
            "rejected durable bytes must remain intact until explicit clear");
    const auto cleared = store.clear(fixture.sha);
    require(
        cleared.identity.epoch != current.identity.epoch &&
            store.status(fixture.sha).error.empty(),
        "explicit clear must recover from corrupt and unknown-version state");
    SessionStore reopened(fixture.directory);
    current = reopened.load(fixture.sha, fixture.binary.string());
    require(current.identity == cleared.identity && current.analysis.empty() &&
                current.comments.empty(),
            "corrupt-state clear must create a reloadable empty document");
  }
  const std::string longest_comment(64 * 1024, 'x');
  store.set_comment(current.identity, {fixture.sha, fixture.binary.string(), 7},
                    longest_comment);
  SessionStore boundary_reader(fixture.directory);
  require(boundary_reader.load(fixture.sha, fixture.binary.string())
                  .comments.at(0)
                  .text == longest_comment,
          "the full comment-editor capacity must remain reloadable without "
          "truncation");
  const auto before = get(fixture.document());
  require_error(
      [&] {
        store.set_comment(current.identity,
                          {fixture.sha, fixture.binary.string(), 7},
                          std::string(64 * 1024 + 1, 'x'));
      },
      "comments beyond the editor capacity must fail before replacing durable "
      "state");
  require(get(fixture.document()) == before,
          "a bounded-write rejection must retain the previous durable state");
  const auto recovered = store.set_comment(
      current.identity, {fixture.sha, fixture.binary.string(), 7},
      "recoverable");
  require(recovered.error.empty() && recovered.comment_count == 1,
          "a successful retry must recover without restarting the store");
  const auto oversized =
      replace(before, longest_comment, longest_comment + "x");
  put(fixture.document(), oversized);
  require_error(
      [&] { boundary_reader.load(fixture.sha, fixture.binary.string()); },
      "externally authored comments beyond editor capacity must be rejected");
  require(
      get(fixture.document()) == oversized,
      "rejecting an oversized stored comment must not overwrite its document");
}

} // namespace

int main() {
  try {
    hash_and_content_identity();
    exact_addresses_unicode_and_order();
    independent_store_merging();
    clear_fences_stale_writes();
    malformed_version_and_explicit_clear();
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "session_store: %s\n", error.what());
    return 1;
  }
}
