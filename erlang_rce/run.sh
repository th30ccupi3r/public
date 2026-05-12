#!/bin/sh
erl -name vuln@172.17.0.2 -setcookie weakcookie -kernel inet_dist_listen_min 4368 inet_dist_listen_max 4368 -noshell -eval 'io:format("starting~n"), timer:sleep(infinity).' 
