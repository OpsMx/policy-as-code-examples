# This policy denies pipeline execution if a specified application does not have any tags containing any of the required substring.
# To apply this policy globally, remove the condition that checks for a specific application

package opsmx.spinnaker.tagspolicy

# Define a list of required substrings
required_substrings = ["BAPP","DEV"]

deny[msg] {
    # comment below line to use this policy globally for all applications
    input.application == "application_name"
    no_required_substring_tags
        msg := sprintf("Pipeline execution denied: No tag contains any of the required substring '%v'.", [required_substrings])
    }

    # Rule to check if there are no tags containing any of the required substrings
    no_required_substring_tags {
        not any_required_substring_tags
    }

    # Rule to determine if any tag contains any of the required substrings
    any_required_substring_tags {
        some tag
        input.tags[tag].value != null
        substr := required_substrings[_]
        contains(input.tags[tag].value, substr)
    }

