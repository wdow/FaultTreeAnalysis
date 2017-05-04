printf 'topo-128, r=10\n' > timelog

{ time ./ft_analyzer topo-128.cnf -o topo-128-10-out -r 10 ; } 2>> timelog

printf '\ntopo-128, r=100\n' >> timelog

{ time ./ft_analyzer topo-128.cnf -o topo-128-100-out -r 100 ; } 2>> timelog

printf '\ntopo-128, r=1000\n' >> timelog

{ time ./ft_analyzer topo-128.cnf -o topo-128-1000-out -r 1000 ; } 2>> timelog

printf '\ntopo-1024, r=10\n' >> timelog

{ time ./ft_analyzer topo-1024.cnf -o topo-1024-10-out -r 10 ; } 2>> timelog

printf '\ntopo-1024, r=100\n' >> timelog

{ time ./ft_analyzer topo-1024.cnf -o topo-1024-100-out -r 100 ; } 2>> timelog

printf '\ntopo-1024, r=1000\n' >> timelog

{ time ./ft_analyzer topo-1024.cnf -o topo-1024-1000-out -r 1000 ; } 2>> timelog

printf '\ntopo-3456, r=10\n' >> timelog

{ time ./ft_analyzer topo-3456.cnf -o topo-3456-10-out -r 10 ; } 2>> timelog

printf '\ntopo-3456, r=100\n' >> timelog

{ time ./ft_analyzer topo-3456.cnf -o topo-3456-100-out -r 100 ; } 2>> timelog

printf '\ntopo-3456, r=1000\n' >> timelog

{ time ./ft_analyzer topo-3456.cnf -o topo-3456-1000-out -r 1000 ; } 2>> timelog

printf '\ntopo-3456, r=10000\n' > timelog-topo-3456-10000

{ time ./ft_analyzer topo-3456.cnf -o topo-3456-10000-out -r 10000 ; } 2>> timelog-topo-3456-10000

printf '\ncomplete'
