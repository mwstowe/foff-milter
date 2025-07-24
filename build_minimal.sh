#!/bin/bash
gcc -o minimal_test_milter minimal_test_milter.c -lmilter -lpthread
echo "Built minimal_test_milter"
echo "To test: sudo ./minimal_test_milter"
echo "Add to sendmail.mc: INPUT_MAIL_FILTER('minimal-test', 'S=local:/var/run/minimal-test.sock,F=5')"
