"""Session-wide test isolation."""

import os
import tempfile

# Local signing keys created during tests go to a throwaway directory,
# never to the developer's real %LOCALAPPDATA%\ThreatWeaver\keys.
_KEY_DIR = tempfile.mkdtemp(prefix="threatweaver-test-keys-")
os.environ["THREATWEAVER_KEY_DIR"] = _KEY_DIR
# All other per-user state (vault, history, cache, local models, rules) also goes to a throwaway dir.
os.environ["THREATWEAVER_HOME"] = tempfile.mkdtemp(prefix="threatweaver-test-home-")
os.environ.pop("THREATWEAVER_ALLOW_UNSIGNED_MODELS", None)
