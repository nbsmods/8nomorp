#!/usr/bin/env python3
import unittest

import smoke_waydroid as smoke


class SmokeTests(unittest.TestCase):
    def test_stable_process(self):
        self.assertIsNone(smoke.failure(['123', '123', '123']))

    def test_restart_loop_is_failure(self):
        self.assertIn('restarted', smoke.failure(['123', '456']))

    def test_dead_process_is_failure(self):
        self.assertIn('disappeared', smoke.failure(['123', '']))
        self.assertIsNotNone(smoke.failure([]))


if __name__ == '__main__':
    unittest.main()
