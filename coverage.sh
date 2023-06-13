#!/bin/bash
# Requirements:
#   cargo install rustfilt
#   pacman -S llvm grep jq  # or the equivalent for your package manager
# See also:
#   https://doc.rust-lang.org/rustc/instrument-coverage.html

DEMANGER=rustfilt
PAGER=bat  # replace with "less -r" if you're uncool and don't have batcat
PROFILE_FILE=coverage.profdata
COV_OPTS="-use-color -ignore-filename-regex=.cargo/registry"
SHOW_OPTS="-show-instantiations -show-line-counts-or-regions"

function get_bins() {
    first=true
    for file in $( \
        RUSTFLAGS="-C instrument-coverage" \
        cargo test --tests --no-run --message-format=json \
        | jq -r "select(.profile.test == true) | .filenames[]" \
        | grep -v dSYM - \
        );
    do
        if [[ "$first" == "true" ]]; then
            printf "%s " $file;
            first=false;
        else
            printf "%s %s " -object $file;
        fi
    done
}

function run() {
    RUSTFLAGS="-C instrument-coverage" cargo test --tests
    llvm-profdata merge -sparse default_*.profraw -o $PROFILE_FILE
}

function report() {
    local bins=$(get_bins)
    llvm-cov report $COV_OPTS -instr-profile=$PROFILE_FILE $bins $@ | $PAGER
}

function show() {
    local bins=$(get_bins)
    llvm-cov show $COV_OPTS -instr-profile=$PROFILE_FILE $bins $SHOW_OPTS $@ | $PAGER
}

function help() {
	read -r -d '' usage <<-EOF
	Usage: ./coverage.sh COMMAND [FILE...]

	Run source-based coverge tools against the source.

	Commands:

	    help
	            Print this message and exist (same as -h).

	    run
                    Build and run instrumented tests, and collect the
                    instrutructions profile.

	    report

                    Show the coverage report for the code line, or individual
                    files if specified as arguemts.

	    show

                    Show source listings, with coverage information
                    superimposed, for the  code line or individual files if
                    specified as arguements.
	EOF
	echo "$usage"
}

command=$1
shift
case $command in
    help) help;;
    run) run;;
    report) report $@;;
    show) show $@;;
    *) echo "ERROR: unknown command \"$command\"; use \"help\" to see usage."
esac
