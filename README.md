撞库流量伪装成正常浏览器，指纹里明明写了自动化特征，判定却给了满分放行：判定必须按来源可信度加权，不得把不同来源的信号简单相加；互相矛盾的信号必须取更严格结论；单一弱信号不得触发封禁；分数必须钳制在既定区间内；同一会话重复上报同信号只算一次；批量判定时各会话必须彼此独立。不变量：同一组信号两次判定结果相同；矛盾信号不会同时得出放行与封禁。

## 输入

策略对象至少包含以下字段：

```python
{
    "source_weights": {
        "browser": 0.9,
        "behavior": 0.6,
        "proxy": 0.2,
        "automation": 1.0,
        "reputation": 0.5,
    },
    "challenge_threshold": 30.0,
    "block_threshold": 70.0,
    "score_min": 0.0,
    "score_max": 100.0,
    "strict_rule": "deny_overrides",
    "weak_confidence_max": 0.3,
    "weak_weight_max": 0.2,
    "unknown_source_weight": 0.5,
}
```

信号对象是包含名称、数值、来源的字典，可带会话标识、结论与置信度。结论取值为 allow、challenge 或 block。解析函数也接受 source:name=value 形式的文本。

## 公开接口

- parse_signals：把原始信号解析为规范化字典列表。
- weight_of：返回信号来源对应的可信度权重。
- resolve_conflict：返回一组信号中最严格的结论。
- score：返回加权并钳制后的风险分数。
- decide：按阈值返回 allow、challenge 或 block。
- dedupe：按会话与信号名去重。
- validate_policy：返回策略问题代码列表。
- bot_batch：按会话独立判定，返回会话到结果的映射。

## 测试

在仓库根目录运行：

```bash
python -m pytest tests -q
```

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

