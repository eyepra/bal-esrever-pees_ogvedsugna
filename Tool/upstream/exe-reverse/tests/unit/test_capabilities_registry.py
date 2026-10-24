"""Unit tests for skills/exe-reverse/scripts/capabilities.py, the capability registry.

The registry's value is that a verdict is *computed* from a probed closure rather than read off a
name, so what is asserted here is the table it computes over: every atom a capability names, every
atom's kind and basis, and the transitive closure the resolution walks.

One part of the table is not well formed, and the tests pin the exact extent rather than asserting
the invariant that fails. `Probe.atom` answers "atom is not defined" for an id with no `ATOMS` row,
so a capability naming a *capability* in `required` or `any_of` has an atom nothing can ever
satisfy. Two rows do that today (`dump_capture`, `hypervisor_observe`); they are named in
`UNTABLED_REFERENCES` so a third one fails the suite instead of arriving silently. Reported as a
defect in the digest: these tests do not repair the script.

`declared_capability` gets its own group, because the convention it reads is documented inside this
file's own docstring. A looser pattern once read that documentation as a declaration and reported
the registry itself as declaring `capability: <capability_id>[, <capability_id>]`; the template is
pinned as *not* a declaration below.
"""
import os

import pytest

pytestmark = pytest.mark.unit

# Measured, not assumed: the `required` / `any_of` entries that name a capability id instead of an
# atom id. Both are answered by `Probe.atom` with the literal detail "atom is not defined", which is
# pinned separately -- the mechanism is what makes the reference unrepairable from outside the file.
UNTABLED_REFERENCES = frozenset({
    ("dump_capture", "any_of", "commandline_debug"),
    ("hypervisor_observe", "required", "kernel_driver_load"),
})

# The kinds `Probe.atom` dispatches on, and the field each one is probed through.
PROBE_HANDLED_KINDS = {
    "python": None,
    "module": "module",
    "tool": "tool",
    "file": "script",
    "host": "probe",
    "artifact": None,
}

# The probe names `_host_flag` understands. Not decoration: a `host` atom whose probe name is not in
# this set falls through to `None`, which reads as "not available on this host" forever.
HOST_PROBE_NAMES = frozenset({
    "elevation", "hypervisor", "intel_pt", "breakpoints", "test_signing", "etw",
})

# Both are the documented strength labels of the *measurement*, not of the route.
BASIS_LABELS = frozenset({"observed", "unverified"})


def probe(caps):
    """A fresh probe with no extra tool directories, so PATH alone decides."""
    return caps.Probe(tool_dirs=[])


def untabled_references(caps):
    out = set()
    for capability_id, spec in caps.CAPABILITIES.items():
        for key in ("required", "any_of"):
            for atom in spec.get(key, []):
                if atom not in caps.ATOMS:
                    out.add((capability_id, key, atom))
    return out


def reference_closure(caps, capability_id):
    """An independent breadth-first walk to compare the module's ordering against."""
    out, queue = [], [capability_id]
    while queue:
        current = queue.pop(0)
        if current in out:
            continue
        out.append(current)
        queue.extend(caps.CAPABILITIES.get(current, {}).get("depends_on", []))
    return out


# --- the atom table ----------------------------------------------------------

def test_the_registry_is_not_empty(load_script):
    caps = load_script("capabilities.py")
    assert len(caps.ATOMS) > 1
    assert len(caps.CAPABILITIES) > 1


def test_every_capability_row_carries_a_name_and_a_required_list(load_script):
    caps = load_script("capabilities.py")
    for capability_id, spec in caps.CAPABILITIES.items():
        assert spec.get("name"), "%s has no name" % capability_id
        required = spec.get("required")
        assert isinstance(required, list), "%s has no required list" % capability_id
        # An empty `required` is legitimate when the row's prerequisites are other capabilities:
        # `hypervisor_observe` needs no atom of its own, it needs the capability below it. What is
        # not legitimate is a row that names nothing at all, because then no probe can decide it.
        assert required or spec.get("any_of") or spec.get("depends_on"), \
            "%s names nothing at all" % capability_id


def test_capability_rows_use_only_the_documented_keys(load_script):
    caps = load_script("capabilities.py")
    allowed = {"name", "required", "any_of", "depends_on", "scripts", "note"}
    for capability_id, spec in caps.CAPABILITIES.items():
        assert set(spec) <= allowed, "%s carries %r" % (capability_id, sorted(set(spec) - allowed))


def test_no_unrecorded_atom_reference_is_outside_the_atom_table(load_script):
    """Every name in a `required` or `any_of` list has a row in the atom table.

    This was false for two entries: a **capability** id had been written into an atom slot, so the
    probe answered `atom is not defined` and the branch could never be satisfied -- and one of them,
    `hypervisor_observe`, was therefore permanently blocked with no next action to print. A slot
    whose vocabulary is wrong is silent, which is why it is asserted as a property now rather than
    as the measured extent of the breakage.
    """
    caps = load_script("capabilities.py")
    assert untabled_references(caps) == set()


def test_a_capability_named_where_an_atom_belongs_is_answered_as_undefined(load_script):
    """The mechanism behind the pinned deviation, so the two rows are not merely suspicious names."""
    caps = load_script("capabilities.py")
    for _capability_id, _key, named in sorted(UNTABLED_REFERENCES):
        assert named in caps.CAPABILITIES, "%s should be a capability id" % named
        result = probe(caps).atom(named)
        assert result["ok"] is False
        assert result["detail"] == "atom is not defined"


def test_dependencies_name_capabilities_rather_than_atoms(load_script):
    """`depends_on` is a capability edge. An atom id here would be silently unresolvable."""
    caps = load_script("capabilities.py")
    for capability_id, spec in caps.CAPABILITIES.items():
        for dep in spec.get("depends_on", []):
            assert dep in caps.CAPABILITIES, \
                "%s depends on %r, which is not a capability" % (capability_id, dep)
            assert dep not in caps.ATOMS, \
                "%s depends on %r, which is an atom: closure() would treat it as a capability" \
                % (capability_id, dep)
            assert dep != capability_id, "%s depends on itself" % capability_id


def test_the_script_map_points_only_at_capabilities_that_exist(load_script):
    caps = load_script("capabilities.py")
    assert caps.SCRIPT_CAPABILITIES
    for script, ids in caps.SCRIPT_CAPABILITIES.items():
        assert ids, "%s is mapped to an empty list, which reads as a claim" % script
        for capability_id in ids:
            assert capability_id in caps.CAPABILITIES, \
                "%s is mapped to unknown capability %r" % (script, capability_id)


def test_the_dependency_graph_is_acyclic(load_script):
    """A cycle would make `resolve` recurse forever rather than report a blocked capability."""
    caps = load_script("capabilities.py")
    state = {}

    def walk(capability_id):
        stack = state.get(capability_id, 0)
        assert stack != 1, "dependency cycle through %s" % capability_id
        if stack == 2:
            return
        state[capability_id] = 1
        for dep in caps.CAPABILITIES.get(capability_id, {}).get("depends_on", []):
            walk(dep)
        state[capability_id] = 2

    for capability_id in caps.CAPABILITIES:
        walk(capability_id)


def test_every_atom_carries_the_basis_label_the_registry_documents(load_script):
    caps = load_script("capabilities.py")
    for atom_id, spec in caps.ATOMS.items():
        assert spec.get("basis") in BASIS_LABELS, \
            "%s has basis %r, which is neither %s" % (atom_id, spec.get("basis"),
                                                      " nor ".join(sorted(BASIS_LABELS)))


def test_every_atom_kind_is_one_the_probe_handles(load_script):
    caps = load_script("capabilities.py")
    for atom_id, spec in caps.ATOMS.items():
        assert spec.get("kind") in PROBE_HANDLED_KINDS, \
            "%s has kind %r, which Probe.atom does not dispatch on" % (atom_id, spec.get("kind"))


def test_every_atom_carries_the_field_its_kind_is_probed_through(load_script):
    """`Probe.atom` subscripts these keys, so a missing one is a KeyError, not a verdict."""
    caps = load_script("capabilities.py")
    for atom_id, spec in caps.ATOMS.items():
        field = PROBE_HANDLED_KINDS[spec["kind"]]
        if field is not None:
            assert spec.get(field), "%s (%s) has no %r" % (atom_id, spec["kind"], field)


def test_every_host_atom_names_a_probe_the_host_reader_implements(load_script):
    caps = load_script("capabilities.py")
    for atom_id, spec in caps.ATOMS.items():
        if spec["kind"] == "host":
            assert spec["probe"] in HOST_PROBE_NAMES, \
                "%s probes %r, which _host_flag does not answer (it would be false forever)" \
                % (atom_id, spec["probe"])


def test_atom_ids_are_prefixed_with_their_kind(load_script):
    caps = load_script("capabilities.py")
    for atom_id, spec in caps.ATOMS.items():
        if spec["kind"] == "python":
            continue
        assert atom_id.startswith(spec["kind"] + ":"), \
            "%s does not name its kind (%s)" % (atom_id, spec["kind"])


def test_every_atom_answers_something_other_than_undefined(load_script):
    """Each row is reachable through the probe: no row falls through to the undefined branch."""
    caps = load_script("capabilities.py")
    p = probe(caps)
    for atom_id in caps.ATOMS:
        result = p.atom(atom_id)
        assert isinstance(result.get("ok"), bool), "%s answered %r" % (atom_id, result)
        assert result["detail"] != "atom is not defined", \
            "%s has a row but the probe still calls it undefined" % atom_id


def test_which_falls_back_to_an_extra_directory(load_script, tmp_path):
    """A tool that is installed off PATH is not a missing tool, which is the whole point of the
    second search path. The file is never executed -- only its presence is checked."""
    caps = load_script("capabilities.py")
    tools = tmp_path / "unpacked"
    tools.mkdir()
    (tools / "ghidra_off_path_probe").write_text("", encoding="utf-8")
    p = caps.Probe(tool_dirs=[str(tools)])
    found, via = p.which("ghidra_off_path_probe")
    assert found == str(tools / "ghidra_off_path_probe")
    assert via == "EXEREV_TOOLS"
    assert p.which("no_such_tool_anywhere_xyz") == (None, None)


def test_extra_tool_dirs_reads_both_environment_variable_names(load_script, monkeypatch, tmp_path):
    caps = load_script("capabilities.py")
    monkeypatch.setenv("EXEREV_TOOLS", str(tmp_path / "one"))
    monkeypatch.setenv("EXE_REVERSE_TOOLS", str(tmp_path / "two") + os.pathsep +
                       str(tmp_path / "three"))
    assert caps.extra_tool_dirs() == [str(tmp_path / "one"), str(tmp_path / "two"),
                                      str(tmp_path / "three")]
    monkeypatch.delenv("EXEREV_TOOLS")
    monkeypatch.delenv("EXE_REVERSE_TOOLS")
    assert caps.extra_tool_dirs() == []


# --- closure -----------------------------------------------------------------

def test_closure_of_a_capability_with_no_dependencies_is_its_only_member(load_script):
    caps = load_script("capabilities.py")
    assert caps.closure("pe_structure_read") == ["pe_structure_read"]


def test_closure_matches_an_independent_walk_over_the_real_table(load_script):
    caps = load_script("capabilities.py")
    for capability_id in caps.CAPABILITIES:
        expected = reference_closure(caps, capability_id)
        assert caps.closure(capability_id) == expected, capability_id


def test_closure_terminates_and_lists_each_capability_once(load_script):
    caps = load_script("capabilities.py")
    for capability_id in caps.CAPABILITIES:
        chain = caps.closure(capability_id)
        assert chain[0] == capability_id
        assert len(chain) == len(set(chain)), "%s repeats a member: %r" % (capability_id, chain)
        assert set(chain) <= set(caps.CAPABILITIES), \
            "%s reaches something that is not a capability: %r" % (capability_id, chain)


def test_closure_follows_more_than_one_hop_and_deduplicates_a_diamond(load_script, monkeypatch):
    """Synthetic: the real table is only one hop deep, so a diamond is built to reach the walk."""
    caps = load_script("capabilities.py")
    for name, deps in (("synthetic_top", ["synthetic_left", "synthetic_right"]),
                       ("synthetic_left", ["synthetic_bottom"]),
                       ("synthetic_right", ["synthetic_bottom"]),
                       ("synthetic_bottom", [])):
        monkeypatch.setitem(caps.CAPABILITIES, name,
                            {"name": name, "required": ["python310"], "depends_on": deps})
    assert caps.closure("synthetic_top") == ["synthetic_top", "synthetic_left",
                                             "synthetic_right", "synthetic_bottom"]


def test_closure_of_an_id_that_is_not_a_capability_is_the_id_alone(load_script):
    """Documented behaviour: no error, no members. Pinned so a caller can see what it gets."""
    assert load_script("capabilities.py").closure("no_such_capability") == ["no_such_capability"]


# --- resolve -----------------------------------------------------------------

def synthetic_capability(monkeypatch, caps, capability_id, **spec):
    body = {"name": "Synthetic " + capability_id, "required": ["python310"]}
    body.update(spec)
    monkeypatch.setitem(caps.CAPABILITIES, capability_id, body)


def test_resolve_reports_blocked_and_names_the_missing_atom(load_script, monkeypatch):
    caps = load_script("capabilities.py")
    synthetic_capability(monkeypatch, caps, "synthetic_missing",
                         required=["python310", "artifact:sample"])
    result = caps.resolve("synthetic_missing", probe(caps))
    assert result["state"] == "blocked"
    assert [atom for atom, _detail in result["missing"]] == ["artifact:sample"]


def test_resolve_of_a_real_capability_names_the_artifact_it_cannot_probe(load_script):
    """`artifact:sample` is operator-supplied by design, so this verdict is stable on any host."""
    caps = load_script("capabilities.py")
    result = caps.resolve("commandline_debug", probe(caps))
    assert result["state"] == "blocked"
    assert "artifact:sample" in [atom for atom, _detail in result["missing"]]


def test_resolve_reports_a_blocked_dependency_by_name(load_script):
    caps = load_script("capabilities.py")
    result = caps.resolve("hardware_breakpoint", probe(caps))
    assert result["state"] == "blocked"
    assert "commandline_debug" in [dep for dep, _state in result["blocked_deps"]]


def test_resolve_on_a_file_atom_follows_the_disk(load_script):
    """A shipped script is present, and the verdict says which path was looked at."""
    caps = load_script("capabilities.py")
    result = caps.resolve("pe_structure_read", probe(caps))
    assert result["state"] == "ok"
    assert result["missing"] == []
    file_atom = probe(caps).atom("file:peutil.py")
    assert file_atom["ok"] is True
    assert file_atom["detail"] == os.path.join(caps.HERE, "peutil.py")


def test_resolve_on_a_fabricated_file_atom_is_missing_and_names_its_path(load_script,
                                                                       monkeypatch):
    caps = load_script("capabilities.py")
    monkeypatch.setitem(caps.ATOMS, "file:no_such_script_xyz.py",
                        {"name": "Fabricated", "kind": "file", "basis": "observed",
                         "script": "no_such_script_xyz.py", "est_minutes": 0})
    synthetic_capability(monkeypatch, caps, "synthetic_file",
                         required=["file:no_such_script_xyz.py"])
    result = caps.resolve("synthetic_file", probe(caps))
    assert result["state"] == "blocked"
    atom, detail = result["missing"][0]
    assert atom == "file:no_such_script_xyz.py"
    assert detail.endswith("no_such_script_xyz.py")


def test_resolve_reports_the_alternatives_it_found(load_script, monkeypatch):
    caps = load_script("capabilities.py")
    synthetic_capability(monkeypatch, caps, "synthetic_any",
                         required=[], any_of=["file:peutil.py", "artifact:sample"])
    result = caps.resolve("synthetic_any", probe(caps))
    assert result["alternatives_present"] == ["file:peutil.py"]
    assert result["state"] == "ok"
    assert result["missing"] == []


def test_resolve_of_an_unknown_capability_is_none(load_script):
    caps = load_script("capabilities.py")
    assert caps.resolve("no_such_capability", probe(caps)) is None


def test_resolve_all_covers_every_capability_and_agrees_with_resolve(load_script):
    caps = load_script("capabilities.py")
    p = probe(caps)
    rows = caps.resolve_all(p)
    assert [row["id"] for row in rows] == list(caps.CAPABILITIES)
    for row in rows:
        assert row == caps.resolve(row["id"], p)


def test_verdict_is_ok_only_when_every_row_is_ok(load_script):
    caps = load_script("capabilities.py")
    assert caps.verdict([]) == ("ok", 0)
    assert caps.verdict([{"state": "ok"}, {"state": "ok"}]) == ("ok", 0)
    assert caps.verdict([{"state": "ok"}, {"state": "blocked"}]) == ("blocked", 3)


def test_human_report_marks_every_row_and_explains_a_blocked_one(load_script):
    caps = load_script("capabilities.py")
    rows = [
        {"id": "ok_one", "name": "Okay", "state": "ok", "missing": [], "blocked_deps": []},
        {"id": "blocked_one", "name": "Blocked", "state": "blocked",
         "missing": [("artifact:sample", "operator supplied; not detectable from here")],
         "blocked_deps": [("other_cap", "blocked")]},
    ]
    quiet = caps.human_report(rows, verbose=False)
    assert any("ok_one" in line and line.startswith("  ok ") for line in quiet)
    assert any("blocked_one" in line and line.startswith("  BLK") for line in quiet)
    loud = caps.human_report(rows, verbose=True)
    assert any("missing atom : artifact:sample" in line for line in loud)
    assert any("blocked by   : other_cap (blocked)" in line for line in loud)


# --- declaration parsing -----------------------------------------------------

def write_script(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_declared_capability_reads_a_single_id(load_script, tmp_path):
    caps = load_script("capabilities.py")
    path = write_script(tmp_path, "one.py",
                        '"""capability: byte_patch\n\nA script that declares its capability.\n"""\n')
    assert caps.declared_capability(str(path)) == ["byte_patch"]


def test_declared_capability_reads_a_comma_separated_list(load_script, tmp_path):
    caps = load_script("capabilities.py")
    path = write_script(tmp_path, "two.py",
                        '"""capability: byte_patch, pe_structure_read\n\nTwo of them.\n"""\n')
    assert caps.declared_capability(str(path)) == ["byte_patch", "pe_structure_read"]


def test_declared_capability_rejects_the_documentation_template(load_script, tmp_path):
    """The exact line this registry's own docstring uses to describe the convention.

    It was once read as a declaration, which reported the registry as declaring a capability named
    `<capability_id>`. A template is not a declaration, and the pin is on that exact string.
    """
    caps = load_script("capabilities.py")
    template = "    capability: <capability_id>[, <capability_id>]"
    path = write_script(tmp_path, "template.py", '"""%s\n\nProse.\n"""\n' % template)
    assert caps.declared_capability(str(path)) == []


def test_the_template_really_does_live_in_the_registrys_own_docstring(load_script):
    """The pin above is only meaningful if the string it names is really in this file."""
    caps = load_script("capabilities.py")
    source = open(os.path.join(caps.HERE, "capabilities.py"), encoding="utf-8").read()
    assert "capability: <capability_id>[, <capability_id>]" in source
    assert caps.declared_capability(os.path.join(caps.HERE, "capabilities.py")) == []


def test_declared_capability_reads_a_real_declaring_script(load_script):
    caps = load_script("capabilities.py")
    assert caps.declared_capability(os.path.join(caps.HERE, "dart_snapshot_strings.py")) == \
        ["static_disassembly"]


@pytest.mark.parametrize("name,body,expected", [
    ("prose.py", '"""No declaration here, only prose.\n\nMore prose.\n"""\n', []),
    ("no-docstring.py", "import os\n", []),
    ("template-only.py", '"""\ncapability: <capability_id>\n"""\n', []),
    ("not-a-list.py", '"""capability: one two\n"""\n', []),
    ("trailing-junk.py", '"""capability: one # comment\n"""\n', []),
    ("hyphenated-id.py", '"""capability: byte-patch\n"""\n', []),
    ("space-before-colon.py", '"""capability : byte_patch\n"""\n', []),
    ("list-with-a-hyphen.py", '"""capability: byte_patch, pe-structure\n"""\n', []),
    ("trailing-space-and-comma.py", '"""capability: byte_patch,\n"""\n', []),
])
def test_declared_capability_refuses_a_shape_that_is_not_a_declaration(load_script, tmp_path,
                                                                      name, body, expected):
    caps = load_script("capabilities.py")
    assert caps.declared_capability(str(write_script(tmp_path, name, body))) == expected


def test_declared_capability_matches_case_insensitively(load_script, tmp_path):
    """Pinned, because it is wider than the ids it can name: the pattern is compiled `(?i)`, so a
    mixed-case declaration is returned verbatim and then resolves to nothing -- every id in both
    tables is lowercase. Recorded as an observation rather than asserted as desirable."""
    caps = load_script("capabilities.py")
    path = write_script(tmp_path, "mixed-case.py", '"""capability: BytePatch\n"""\n')
    assert caps.declared_capability(str(path)) == ["BytePatch"]
    assert "BytePatch" not in caps.CAPABILITIES


def test_declared_capability_is_silent_about_a_file_it_cannot_read(load_script, tmp_path):
    caps = load_script("capabilities.py")
    assert caps.declared_capability(str(tmp_path / "absent.py")) == []
    broken = write_script(tmp_path, "broken.py", '"""capability: byte_patch\n"""\nif True print)\n')
    assert caps.declared_capability(str(broken)) == []


# --- script -> capability ----------------------------------------------------

def test_capabilities_for_script_reports_a_declaration(load_script):
    caps = load_script("capabilities.py")
    path = os.path.join(caps.HERE, "dart_snapshot_strings.py")
    assert caps.capabilities_for_script("dart_snapshot_strings.py", path) == \
        (["static_disassembly"], "declared")


def test_capabilities_for_script_falls_back_to_the_map(load_script):
    caps = load_script("capabilities.py")
    assert caps.capabilities_for_script("aob_scan.py") == (["aob_locate"], "mapped")


def test_capabilities_for_script_prefers_the_declaration_over_the_map(load_script, tmp_path):
    """A script may not be silently reclassified by the map once it declares its own capability."""
    caps = load_script("capabilities.py")
    path = write_script(tmp_path, "aob_scan.py",
                        '"""capability: pe_structure_read\n\nDeclares what it is.\n"""\n')
    assert caps.capabilities_for_script("aob_scan.py", str(path)) == \
        (["pe_structure_read"], "declared")


def test_a_script_in_neither_table_is_unknown_rather_than_empty_and_claimed(load_script, tmp_path):
    caps = load_script("capabilities.py")
    path = write_script(tmp_path, "stranger.py", '"""Nothing is claimed here.\n"""\n')
    ids, source = caps.capabilities_for_script("stranger.py", str(path))
    assert (ids, source) == ([], "unknown")
    assert source != "mapped", "an unknown script must not be reported as mapped to nothing"
