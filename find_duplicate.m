#! /opt/local/bin/octave-cli -qf

clear all;

printf('Data analysis\n');

tic;
load analyse.dat;
[D,~,X] = unique(data);
[n, bin] = histc(X,unique(X));
multiple = find(n > 1);
index = find(ismember(bin, multiple));
toc;

printf('Result is:\n');
index
