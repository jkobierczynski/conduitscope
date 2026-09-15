// SPDX-License-Identifier: MIT
// yaml_mini.hpp - a minimal, purpose-built parser for the restricted YAML
// subset conduitscope's zone/conduit policy files use (see policy.hpp).
//
// This is NOT a general-purpose YAML parser and never will be: conduitscope
// has zero external dependencies by design (see CMakeLists.txt -- CLI11 is
// the only vendored third-party code, and that's a command-line-parsing
// header, not a data-format one), and a correct, complete YAML 1.2
// implementation is out of scope for what a zone/conduit policy file
// actually needs to express. What's supported is exactly the "block-style
// YAML" most hand-written config files already use:
//   - block mappings: "key: value" lines, nested by indentation (2+ spaces
//     deeper than their parent)
//   - block sequences: "- item" lines, including the "list of mappings"
//     shape ("- name: x" starting an item, with sibling keys "from: y" on
//     following lines indented to line up under "name")
//   - flow sequences of scalars only, e.g. "[502, 503]" or "[modbus, dnp3]"
//     (no nested flow sequences or flow mappings inside them)
//   - double- and single-quoted scalars ("like this", 'like this'), and
//     bare (unquoted) scalars
//   - "#" comments (a line's own indentation, or whitespace before the
//     "#", is what marks a comment -- a "#" inside a quoted scalar is NOT
//     treated as a comment start)
//   - blank lines, freely
// Deliberately NOT supported -- and rejected with YamlError rather than
// silently misparsed, wherever this parser actually notices them: anchors
// and aliases ("&x", "*x"), tags ("!!str"), multi-document streams ("---",
// "..."), block scalars ("|", ">"), flow mappings ("{a: b}"), and tab
// characters used for indentation. None of these add anything a zone/
// conduit policy file needs to say.
#pragma once

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace conduitscope::yaml_mini {

enum class NodeType { Null, Scalar, Sequence, Mapping };

struct Node {
    NodeType type = NodeType::Null;
    std::string scalar;                                   // NodeType::Scalar
    std::vector<Node> sequence;                            // NodeType::Sequence
    std::vector<std::pair<std::string, Node>> mapping;     // NodeType::Mapping, insertion order kept
    int line = 0;  // 1-based source line this node's content begins on (best-effort, for errors)

    // Returns the value mapped to `key` if this is a Mapping node and has that key, else nullptr.
    // (Not a map/hashtable lookup -- policy files have a handful of keys per mapping, so linear
    // scan over `mapping` is simpler than an ordered-map type and just as fast in practice.)
    const Node* find(const std::string& key) const;
};

// Thrown for anything outside the supported subset above, or for structurally inconsistent
// indentation (e.g. a line indented to a level no enclosing block opened). `line` is the 1-based
// source line the problem was detected on; `what()` is a human-readable message that does NOT
// itself repeat the line number (callers -- see policy.cpp -- prefix "<source>:<line>: " themselves
// so every PolicyError has one consistent format regardless of whether it originated here or in
// policy.cpp's own schema validation).
struct YamlError : std::runtime_error {
    YamlError(const std::string& msg, int line_) : std::runtime_error(msg), line(line_) {}
    int line;
};

// Parses `text` (a whole policy file's contents) into a tree rooted at a single top-level node --
// a Mapping for any well-formed policy file, or Null if `text` is empty or entirely blank/comment
// lines. Throws YamlError on any construct outside the supported subset described above, or on
// inconsistent indentation.
Node parse(const std::string& text);

}  // namespace conduitscope::yaml_mini
