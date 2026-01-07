#!/bin/bash

TESTS="generic/490 generic/504 generic/519 generic/523 generic/524 generic/528 generic/531 generic/532 generic/533 generic/535 generic/538 generic/551 generic/557 generic/564 generic/571 generic/591 generic/598 generic/604 generic/609 generic/611 generic/650"


for i in $(seq 0 20); do
       sudo ./check $TESTS
done
