from tests_cnf.conftest import validates
import pytest
import subprocess
import tarfile
import tempfile
import os
from tests_cnf.conftest import optional_tests_settings as tests
import yaml


@pytest.fixture
def helm_package_path(helm_package):
    assert tarfile.is_tarfile(helm_package.path), "{} is a invalid tgz file".format(
        helm_package.name
    )
    archive = tarfile.open(helm_package.path)
    target_dir = tempfile.TemporaryDirectory().name
    archive.extractall(path=target_dir)
    return target_dir


@validates("R-C00016")
def test_helm_lint(helm_package):
    if "strict_helm_lint" in tests and tests["strict_helm_lint"]:
        retcode = subprocess.run(
            [
                "helm",
                "lint",
                os.path.join(helm_package.path),
                "--with-subcharts",
                "--strict",
            ],
            capture_output=True,
        )
        assert (
            retcode.returncode == 0
        ), "'helm lint --strict' failed on package {}. \n Lint result: \n {}".format(
            helm_package.name, retcode.stdout.decode("utf-8")
        )
    else:
        retcode = subprocess.run(
            ["helm", "lint", os.path.join(helm_package.path), "--with-subcharts"],
            capture_output=True,
        )
        assert (
            retcode.returncode == 0
        ), "'helm lint' failed on package {}. \n Lint result \n {}".format(
            helm_package.name, retcode.stdout.decode("utf-8")
        )


@validates("R-C00022")
@pytest.mark.skipif(
    "helm_verify_integrity" in tests and not tests["helm_verify_integrity"],
    reason="Test disabled",
)
def test_helm_verify_integerity(helm_package):
    assert tarfile.is_tarfile(helm_package.path), "{} is a invalid tgz file".format(
        helm_package.name
    )
    retcode = subprocess.run(
        ["helm", "verify", os.path.join(helm_package.path)], capture_output=True
    )
    assert (
        retcode.returncode == 0
    ), "'helm verify' failed on package {}. \n Verification result: \n {}".format(
        helm_package.name, retcode.stdout.decode("utf-8")
    )


@pytest.fixture
def helm_chart_dir(helm_package_path):
    chart_dir_name = os.listdir(helm_package_path)[0]
    return os.path.join(helm_package_path, chart_dir_name)


@validates("R-C00019")
@pytest.mark.skipif(
    "license_present_in_helm" in tests and not tests["license_present_in_helm"],
    reason="Test disabled",
)
def test_license_present_in_helm(helm_chart_dir):
    assert os.path.exists(
        os.path.join(helm_chart_dir, "LICENSE")
    ), "LICENSE missing from chart : {}".format(os.path.basename(helm_chart_dir))


@validates("R-C00020")
@pytest.mark.skipif(
    "readme_present_in_helm" in tests and not tests["readme_present_in_helm"],
    reason="Test disabled",
)
def test_readme_present_in_helm(helm_chart_dir):
    assert os.path.exists(
        os.path.join(helm_chart_dir, "README.md")
    ), "README.md missing from chart : {}".format(os.path.basename(helm_chart_dir))


@pytest.fixture
def helm_chart_yaml_file_path(helm_chart_dir):
    yaml_file_path = os.path.join(helm_chart_dir, "Chart.yaml")
    return yaml_file_path


@pytest.fixture
def helm_chart_yaml_data(helm_chart_yaml_file_path):
    return yaml.safe_load(open(helm_chart_yaml_file_path))


@validates("R-C00017")
@pytest.mark.skipif(
    "appVersion_present" in tests and not tests["appVersion_present"],
    reason="Test disabled",
)
def test_appVersion_present(helm_chart_yaml_data):
    assert (
        "appVersion" in helm_chart_yaml_data
    ), "'appVersion' missing from Chart.yaml in package {}".format(
        helm_chart_yaml_data["name"]
    )


@validates("R-C00018")
@pytest.mark.skipif(
    "appVersion_in_quotes" in tests and not tests["appVersion_in_quotes"],
    reason="Test disabled",
)
def test_appVersion_in_quotes(helm_chart_yaml_file_path, helm_chart_yaml_data):
    with open(helm_chart_yaml_file_path) as yaml_content:
        for line in yaml_content:
            if line.strip().startswith("appVersion"):
                line_content = line.strip().split()
                assert (
                    line_content[-1].startswith('"') and line_content[-1].endswith('"')
                ) or (
                    line_content[-1].startswith("'") and line_content[-1].endswith("'")
                ), "'appVersion' is not wrapped in quotes in Chart.yaml in package {}".format(
                    helm_chart_yaml_data["name"]
                )
                break


@validates("R-C00021")
@pytest.mark.skipif(
    "notes_present_in_templates" in tests and not tests["notes_present_in_templates"],
    reason="Test disabled",
)
def test_notes_present_in_templates(helm_chart_dir):
    templates_dir = os.path.join(helm_chart_dir, "templates")
    if os.path.exists(templates_dir):
        assert os.path.exists(
            os.path.join(templates_dir, "NOTES.txt")
        ), "NOTES.txt missing from templates/ in package {}".format(
            os.path.basename(helm_chart_dir)
        )
