import argparse
from datetime import timedelta
import re


def get_sum_time(timestamps: list[timedelta], total_microseconds: float):
    print(f"Syscall was executed {len(timestamps)} times. Took {total_microseconds / 1_000_000 } seconds.", )

def get_average_execution_time(timestamps: list[timedelta], total_microseconds: float):
    average_seconds = total_microseconds / len(timestamps) / 1_000_000
    print(f"Average: {average_seconds:.8f} seconds")

def get_timedelta_from_file_by_syscall_name(filename: str, syscall_name) -> (list[timedelta] , float):
    pattern = f'.*{syscall_name}.*'
    total_microseconds = 0
    timestamps = []
    with open(filename, 'r') as f:
        for line in f:
            if re.match(pattern, line):
                line = line.split(' ')
                try:
                    delta = timedelta(seconds=(float(line[len(line)-1].replace('<','').replace('>',''))))
                    timestamps.append(delta)
                except Exception as e:
                    print(e)
                    continue


    for timestamp in timestamps:
        total_microseconds += timestamp.microseconds
    return timestamps, total_microseconds
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='get trace filename.')
    parser.add_argument('--filename', type=str, help='The name of the file to process')
    parser.add_argument('--syscall', type=str, help='The name of the sys call')
    args = parser.parse_args()
    time_array, total_microseconds = get_timedelta_from_file_by_syscall_name(args.filename, args.syscall)
    get_sum_time(time_array, total_microseconds)
    get_average_execution_time(time_array, total_microseconds)