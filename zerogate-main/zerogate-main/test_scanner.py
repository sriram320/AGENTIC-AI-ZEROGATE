import asyncio

from loguru import logger

from codebase_rag.auto_scanner import AutoScanner


async def test():
    scanner = AutoScanner(host="127.0.0.1", port=7687)
    report = await scanner.run_full_scan("dab484f291144101")
    logger.info(f"Scan complete. {len(report.findings)} findings found.")
    for f in report.findings:
        logger.info(f"Finding: {f.title} ({f.severity})")


if __name__ == "__main__":
    asyncio.run(test())
