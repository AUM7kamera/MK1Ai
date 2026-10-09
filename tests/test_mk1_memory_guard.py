import platform
import resource
import unittest
from typing import cast

import mk1_memory_guard


@unittest.skipUnless(platform.system() == "Linux", "Linux process protections only")
class MemoryGuardTest(unittest.TestCase):
    def tearDown(self):
        if mk1_memory_guard.is_enabled():
            mk1_memory_guard.set_enabled(False)

    def test_process_hardening_can_be_enabled_and_restored(self):
        original_core_limit = resource.getrlimit(resource.RLIMIT_CORE)
        mk1_memory_guard.set_enabled(True)

        self.assertTrue(mk1_memory_guard.is_enabled())
        self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE)[0], 0)
        self.assertEqual(mk1_memory_guard._prctl(mk1_memory_guard._PR_GET_DUMPABLE), 0)
        self.assertEqual(mk1_memory_guard._tracer_pid(), 0)

        mk1_memory_guard.set_enabled(False)

        self.assertFalse(mk1_memory_guard.is_enabled())
        self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE), original_core_limit)

    def test_locked_secret_is_wiped_and_unlocked(self):
        mk1_memory_guard.set_enabled(True)
        secret = bytearray(b"test secret")

        mk1_memory_guard.lock_buffer(secret)
        self.assertIn(id(secret), mk1_memory_guard._LOCKED_BUFFERS)
        mk1_memory_guard.wipe_buffer(secret)

        self.assertEqual(secret, bytearray(len(secret)))
        self.assertNotIn(id(secret), mk1_memory_guard._LOCKED_BUFFERS)
        self.assertFalse(mk1_memory_guard._LOCKED_PAGES)

    def test_enabled_state_requires_boolean(self):
        with self.assertRaises(ValueError):
            mk1_memory_guard.set_enabled(cast(bool, 1))


if __name__ == "__main__":
    unittest.main()
