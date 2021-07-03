from tests_cnf.conftest import validates
import os
import json
import jsonschema


@validates("R-C00002")
def test_manifest_file_present(package_dir):
    json_path = os.path.join(package_dir, "MANIFEST.json")
    assert os.path.exists(json_path), "MANIFEST.json missing"


@validates("R-C00002", "R-C00004", "R-C00005", "R-C00006", "R-C00007")
def test_manifest_valid(json_file, manifest_schema_file):
    try:
        json_data = json.load(json_file)
    except:
        assert 0, "MANIFEST.json in not a valid json file"
    json_schema = json.load(manifest_schema_file)
    try:
        jsonschema.validate(json_data, json_schema)
    except jsonschema.exceptions.ValidationError as e:
        assert 0, "MANIFEST.json does not satisfy requirements. \n {}".format(e.message)


@validates("R-C00009")
def test_all_artifacts_listed(json_data, artifact_files):
    expected_files = set([p.name for p in artifact_files])
    listed_files = set([p["file"] for p in json_data["data"]])
    not_listed_files = expected_files.difference(listed_files)
    assert (
        not not_listed_files
    ), "Following files are not listed in MANIFEST.json {}".format(not_listed_files)


@validates("R-C00010")
def test_all_artifacts_found(json_data, artifact_files):
    expected_files = set([p.name for p in artifact_files])
    listed_files = set([p["file"] for p in json_data["data"]])
    not_found_files = listed_files.difference(expected_files)
    assert (
        not not_found_files
    ), "Following files are not found but are listed MANIFEST.json {}".format(
        not_found_files
    )


@validates("R-C00008")
def test_at_least_one_artifact(json_data):
    listed_files = set([p["file"] for p in json_data["data"]])
    assert listed_files, "At least artifact must be present in the package"


@validates("R-C00011")
def test_no_duplicate_listings(json_data):
    listed_files = [p["file"] for p in json_data["data"]]
    duplicate_entries = [p for p in set(listed_files) if listed_files.count(p) > 1]
    assert (
        not duplicate_entries
    ), "Following files are defined more than once in MANIFEST.json {}".format(
        duplicate_entries
    )


@validates("R-C00013")
def test_HELM_prefix(json_data):
    helm_files_without_prefix = [
        p["file"]
        for p in json_data["data"]
        if (p["type"] == "HELM" and not p["file"].startswith("helm_"))
    ]
    assert (
        not helm_files_without_prefix
    ), "HELM artifact file name should have prefix 'helm_'. Following entries in manifest violate this {}".format(
        helm_files_without_prefix
    )


@validates("R-C00014")
def test_HELM_ext(json_data):
    helm_files_not_tgz = [
        p["file"]
        for p in json_data["data"]
        if (p["type"] == "HELM" and not p["file"].endswith(".tgz"))
    ]
    assert (
        not helm_files_not_tgz
    ), "HELM artifact files should have extension '.tgz'. Following entries in manifest violate this {}".format(
        helm_files_not_tgz
    )


@validates("R-C00013")
def test_HEAT_file_name(json_data):
    heat_files_with_helm = [
        p["file"]
        for p in json_data["data"]
        if (p["type"] == "HEAT" and "helm" in p["file"])
    ]
    assert (
        not heat_files_with_helm
    ), "HEAT artifact file name should not have keyword 'helm' in their name. Following entries in manifest violate this {}".format(
        heat_files_with_helm
    )


@validates("R-C00012", "R-C00015")
def test_isBase_property(json_data):
    isBase_not_defined = [
        p["file"]
        for p in json_data["data"]
        if (p["type"] == "HELM" or p["type"] == "HEAT") and not "isBase" in p
    ]
    assert (
        not isBase_not_defined
    ), '"isBase" property must be defined for HELM and HEAT artifacts. Missing for {}'.format(
        isBase_not_defined
    )

    base_files = [
        (p["file"], p["type"])
        for p in json_data["data"]
        if (p["type"] == "HELM" or p["type"] == "HEAT") and p["isBase"] == "true"
    ]
    assert base_files, 'A artifact must have "isBase": "true" in MANIFEST.json'
    assert (
        len(base_files) == 1
    ), 'Multiple artifacts have "isBase": "true" in MANIFEST.json: {}. Only one is allowed.'.format(
        base_files
    )

    helm_present = any(p["type"] == "HELM" for p in json_data["data"])
    base_type = base_files[0][1]
    if helm_present:
        assert (
            base_type == "HELM"
        ), "Base artifact should be a HELM type, if a HELM artifact is present"
