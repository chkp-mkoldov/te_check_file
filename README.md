
## run directly
```
export TE_API_KEY=TE_API_KEY_O03IRJDJBouilXTg6P5WcWrjWtJ8lO98MvDbgdpC
export TE_TEST_FILE="https://poc-files.threat-cloud.com/demo/demo.doc"

./te_check_file -k $TE_API_KEY -f $TE_TEST_FILE
```

## run with Docker
```
export TE_API_KEY=TE_API_KEY_O03IRJDJBouilXTg6P5WcWrjWtJ8lO98MvDbgdpC
export TE_TEST_FILE="https://poc-files.threat-cloud.com/demo/demo.doc"
mkdir out
docker run -ti --rm -v $(pwd)/out:/out chkpmkoldov/te_check_file -k $TE_API_KEY -f $TE_TEST_FILE
```