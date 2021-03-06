#!/bin/bash

# Check if all examples have correct Makefiles

echo "-----------------------"
echo "--  CHECKING MAKEFILES --"
echo "-----------------------"
echo "ignoring: acceleration/kmeans/"
echo "ignoring: acceleration/high_perf_mat_mult/"
echo "ignoring: getting_started/kernel_to_gmem/kernel_global_bandwidth/"
echo "ignoring: getting_started/rtl_kernels/"
echo "ignoring: security/sha1/"

FAIL=0

check_file() {
	ignore=0

	for i in $IGNORE; do
		if [[ $1 =~ ^description.json ]]; then 
			ignore=1
		fi
	done

	if [[ $VERBOSE == "true" ]]; then
		echo -n "Checking $1 ... "
	fi
	if [[ $ignore == 1 ]]; then
		if [[ $VERBOSE == "true" ]]; then
			echo "SKIP"
		fi
	else
		pushd . > /dev/null
		jsonDir=$(dirname $(readlink -f $1))
		cd $jsonDir
		mv Makefile Makefile.check > /dev/null 2>&1
		$utilityDir/makefile_gen/makegen.py $1 > /dev/null 2>&1
		rc=$?
		diff Makefile Makefile.check 2>/dev/null 1>&2
		if [[ $rc == 0 && $? == 0 ]]; then
			#echo 'pass file'
			if [[ $VERBOSE == "true" ]]; then
				echo "PASS"
			fi
		else
			if [[ $VERBOSE == "true" ]]; then
				echo "FAIL"
				diff Makefile Makefile.check
			else
				echo "$1"
			fi
			(( FAIL += 1 ))
		fi
		mv Makefile.check Makefile > /dev/null 2>&1
		popd >/dev/null
	fi
}

utilityDir=$(dirname $(readlink -f $0))
cd $utilityDir
cd ..
VCS_FILES=$(git ls-files)

for f in $VCS_FILES; do
	if [[ ($f == */description.json) && ($f != */kernel_global_bandwidth/*) && ($f != */kmeans/*) && ($f != */sha1/*) && ($f != */rtl_kernel/*) && ($f != */high_perf_mat_mult/*) ]]; then
		check_file $(readlink -f $f)
	fi
done

if [[ $FAIL != 0 ]]; then
	echo "ERROR: Makefile check failed"
	echo "ERROR: please fix the makefile in these files"
fi

exit $FAIL
