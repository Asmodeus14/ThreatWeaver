"""Session-wide test isolation."""

import os
import tempfile

# Local signing keys created during tests go to a throwaway directory,
# never to the developer's real %LOCALAPPDATA%\ThreatWeaver\keys.
_KEY_DIR = tempfile.mkdtemp(prefix="threatweaver-test-keys-")
os.environ["THREATWEAVER_KEY_DIR"] = _KEY_DIR
os.environ.pop("THREATWEAVER_ALLOW_UNSIGNED_MODELS", None)
