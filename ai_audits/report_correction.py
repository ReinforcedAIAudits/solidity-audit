from pydantic import BaseModel
from solidity_audit_lib.messaging import VulnerabilityReport

REPORTS_PER_REQUEST = 26
NATO_PHONETIC = [
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "xray",
    "yankee",
    "zulu",
]


class MinerResult(BaseModel):
    uid: int
    time: float
    response: list[VulnerabilityReport] | None
    collection_id: int | None = None
    tokens: list[int] | None = None


class ReportAdditionalFields(BaseModel):
    report_id: str
    description: str | None = None
    test_case: str | None = None
    fixed_lines: str | None = None
    vulnerabilityClass: str
    uids: list[int]


class LLMScoring(BaseModel):
    report_id: str
    description_reasons: list[str]
    description_score: float
    test_case_reasons: list[str]
    test_case_score: float
    fixed_lines_reasons: list[str]
    fixed_lines_score: float


class ValidatorEstimation(BaseModel):
    uid: int
    scoring: LLMScoring


def generate_unique_identifier(index: int) -> str:
    return NATO_PHONETIC[index % len(NATO_PHONETIC)]


def create_report_additional_fields(
    responses: list[MinerResult],
) -> list[ReportAdditionalFields]:
    reports = []
    for response in responses:
        if not response.response:
            continue
        for report in response.response:
            reports.append(
                ReportAdditionalFields(
                    report_id="",
                    description=report.description,
                    test_case=report.test_case,
                    fixed_lines=report.fixed_lines,
                    vulnerabilityClass=report.vulnerability_class,
                    uids=[response.uid],
                )
            )
    return reports


def filter_unique_reports_by_fields(
    reports: list[ReportAdditionalFields],
    fields: list[str],
) -> list[ReportAdditionalFields]:
    unique_reports: dict[tuple, ReportAdditionalFields] = {}
    for report in reports:
        key = tuple(getattr(report, field) for field in fields)
        if key in unique_reports:
            unique_reports[key].uids.extend(report.uids)
        else:
            unique_reports[key] = report
    return list(unique_reports.values())


def sort_reports_by_nullable_fields(
    reports: list[ReportAdditionalFields],
    fields: list[str],
) -> list[ReportAdditionalFields]:
    return sorted(reports, key=lambda x: tuple(getattr(x, field) is None for field in fields))


def prepare_reports(
    response: list[MinerResult],
) -> list[list[ReportAdditionalFields]]:
    reports = create_report_additional_fields(response)
    unique_reports = filter_unique_reports_by_fields(reports, ["description", "test_case", "fixed_lines"])
    sorted_reports = sort_reports_by_nullable_fields(unique_reports, ["description", "test_case", "fixed_lines"])

    for i, report in enumerate(sorted_reports):
        report.report_id = generate_unique_identifier(i)

    if len(sorted_reports) <= REPORTS_PER_REQUEST:
        return [sorted_reports]

    return [sorted_reports[i: i + REPORTS_PER_REQUEST] for i in range(0, len(sorted_reports), REPORTS_PER_REQUEST)]


def find_scoring_by_id(
    response: list[LLMScoring],
    report_id: str,
) -> LLMScoring | None:
    for report in response:
        if report.report_id == report_id:
            return report
    return None


def restore_reports(
    reports: list[ReportAdditionalFields],
    response: list[LLMScoring],
) -> list[ValidatorEstimation]:
    scoring_lookup = {scoring.report_id: scoring for scoring in response}

    responses_to_validator = []
    for report in reports:
        scoring = scoring_lookup.get(report.report_id)
        if scoring is None:
            raise ValueError(f"Report with id {report.report_id} not found in response")

        responses_to_validator.extend(ValidatorEstimation(uid=uid, scoring=scoring) for uid in report.uids)

    return responses_to_validator
