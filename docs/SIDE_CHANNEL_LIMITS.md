# Secret-memory and side-channel limitations

The current memory helpers are process-local best-effort controls. They can
disable core dumps for the process, request `mlock` and `MADV_DONTDUMP` for
selected mutable buffers, wipe those buffers, and poll `TracerPid`. They do
not prove that secrets never reach swap, kernel buffers, library temporaries,
registers, caches, or storage; a polling check can miss short-lived tracing.
They cannot defeat a compromised kernel/hypervisor, malicious firmware,
physical observation, or timing, cache, power, fault-injection, Spectre-class,
or Rowhammer attacks.

Current tests verify selected mutable-buffer zeroing/unlocking and process
hardening behavior. They are functional tests, not constant-time or
microarchitectural side-channel evidence. No dudect/ctgrind test currently
establishes constant-time behavior of the complete cryptographic path.

Deployment guidance, not a verified control:

- Disable swap or use a separately reviewed encrypted-swap policy. Do not
  infer whole-system swap safety from a per-process memory helper.
- Disable core dumps system-wide and validate the effective setting after
  boot.
- Consider disabling SMT or pinning sensitive work to dedicated cores where
  supported; neither prevents all shared-resource side channels.
- Minimize secret lifetime, avoid immutable secret copies where possible, and
  use reviewed cryptographic-library zeroization APIs.
- Use independent laboratory testing for timing and physical side channels.

No software-only mitigation here establishes resistance to hardware side
channels. EAL7 or any certification claim is not made.
