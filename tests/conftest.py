# -*- coding: utf-8 -*-
"""pytest 公共配置：把项目根目录加入 sys.path，使测试可直接 ``from lib import ...``。

运行方式（在项目根目录）：
    pytest
    pytest tests/test_gm_codec.py -v
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
