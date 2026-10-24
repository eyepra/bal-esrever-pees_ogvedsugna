// Verification probe for a located branch in a compiled snapshot.
//
// WHY THIS IS A TEMPLATE AND NOT A SCRIPT WITH HARDCODED ADDRESSES
// ----------------------------------------------------------------
// The addresses below belong to one specific build. A probe that ships with them baked in would be
// wrong for every other target, and worse, would appear to run. So the two address slots are
// placeholders to fill from a disassembly pass, and the probe refuses to attach until they are set.
//
// WHAT IT OBSERVES, AND WHY THESE TWO THINGS
// -------------------------------------------
// A gate is decided in one place and reported in another, so a probe that watches only the judge
// cannot tell "the feature ran" from "the feature was never attempted". Watching the pair separates
// the three states that matter:
//
//   judge called, display called      -> the gate fired: still blocked
//   judge called, display not called  -> the gate cleared: the ordinary path was taken
//   neither called                    -> the feature was never exercised, so nothing is learned
//
// The third line is the one that keeps a session honest. An absence of calls is not evidence of an
// unlock; it is evidence that nothing happened.
//
// USAGE
//   frida -f <target.exe> -l gate_probe.js --runtime=v8
//   (or attach to a running instance: frida -n <name> -l gate_probe.js)
//
// Then perform the gated action once, in the application, and read the counters.

'use strict';

// --- fill these in from the disassembly -------------------------------------
var JUDGE_OFFSET = 0x00000000;   // the shared decision function, file/virtual offset
var DISPLAY_OFFSET = 0x00000000; // the shared "show the message and return" routine
var MODULE_NAME = 'app.so';      // the image the snapshot is loaded from
// ----------------------------------------------------------------------------

if (JUDGE_OFFSET === 0 || DISPLAY_OFFSET === 0) {
    console.error('[gate-probe] JUDGE_OFFSET and DISPLAY_OFFSET must be set before use.');
    console.error('[gate-probe] find them with a snapshot front end, then edit this file.');
    console.error('[gate-probe] refusing to attach, because a probe at address 0 would report');
    console.error('[gate-probe] nothing and look like a clean result.');
} else {

    var base = null;
    var judgeCalls = 0;
    var displayCalls = 0;

    function findBase() {
        // A Flutter snapshot is frequently mapped without a module entry, so the fallback scans
        // for the ELF header rather than trusting the module list.
        var m = Process.findModuleByName(MODULE_NAME);
        if (m !== null) {
            return { base: m.base, how: 'module ' + MODULE_NAME };
        }
        var found = null;
        Process.enumerateRanges('r--').forEach(function (range) {
            if (found !== null || range.size < 64) { return; }
            try {
                var head = range.base.readByteArray(4);
                var b = new Uint8Array(head);
                if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
                    found = range.base;
                }
            } catch (e) { /* unreadable range: not it */ }
        });
        return found === null ? null : { base: found, how: 'ELF header scan' };
    }

    function summary() {
        var verdict;
        if (judgeCalls === 0 && displayCalls === 0) {
            verdict = 'NOTHING EXERCISED -- do the gated action once, then read again';
        } else if (displayCalls > 0) {
            verdict = 'STILL BLOCKED -- the display routine ran, so a gate fired';
        } else {
            verdict = 'CLEARED -- the decision was reached and the message was never shown';
        }
        console.log('[gate-probe] judge calls  : ' + judgeCalls);
        console.log('[gate-probe] display calls: ' + displayCalls);
        console.log('[gate-probe] verdict      : ' + verdict);
        return verdict;
    }

    var located = findBase();
    if (located === null) {
        console.error('[gate-probe] could not locate ' + MODULE_NAME + ' in this process.');
        console.error('[gate-probe] the target may not have mapped the snapshot yet;');
        console.error('[gate-probe] attach after the window appears rather than at launch.');
    } else {
        var judgeAddr = located.base.add(JUDGE_OFFSET);
        var displayAddr = located.base.add(DISPLAY_OFFSET);
        console.log('[gate-probe] base 0x' + located.base + ' via ' + located.how);
        console.log('[gate-probe] judge   ' + judgeAddr + '   display ' + displayAddr);

        Interceptor.attach(judgeAddr, {
            onEnter: function () { judgeCalls += 1; },
            onLeave: function (retval) {
                // The return is a tagged boolean; print it raw rather than interpreting it, because
                // which tag means true is the thing this probe exists to help settle.
                console.log('[gate-probe] judge returned ' + retval);
            }
        });

        Interceptor.attach(displayAddr, {
            onEnter: function () { displayCalls += 1; }
        });

        console.log('[gate-probe] attached. Perform the gated action once, then call summary().');
        globalThis.summary = summary;
    }
}
