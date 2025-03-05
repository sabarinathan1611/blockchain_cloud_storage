import psutil
import platform

def convert_bytes(bytes):
    # Convert bytes to a human-readable format
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            break
        bytes /= 1024.0
    return f"{bytes:.2f} {unit}"

class StorageInfo:
    def __init__(self, partition):
        self.partition = partition

    def get_info(self):
        try:
            partition_usage = psutil.disk_usage(self.partition.mountpoint)
            return {
                "Mount Point": self.partition.mountpoint,
                "Total": convert_bytes(partition_usage.total),
                "Used": convert_bytes(partition_usage.used),
                "Free": convert_bytes(partition_usage.free),
                "Percentage Used": partition_usage.percent
            }
        except Exception as e:
            return f"Error reading {self.partition.mountpoint} information: {e}"

class SystemInfo:
    def get_info(self):
        return {
            "OS": f"{platform.system()} {platform.version()}",
            "OS Type": f"{platform.system()} {platform.architecture()[0]}",
            "Python Version": f"{platform.python_version()}"
        }

class SystemInfoPrinter:
    def __init__(self):
        self.storage_info = [StorageInfo(partition) for partition in psutil.disk_partitions()]
        self.system_info = SystemInfo()

    def print_storage_info(self):
        print("Storage Information:")
        storage_info_list = []  # Accumulate storage information for all partitions
        for storage in self.storage_info:
            info = storage.get_info()
            storage_info_list.append(info)
            print(info)  # Optionally, print each partition's information to console
        return storage_info_list  # Return the list of storage information

    def print_system_info(self):
        print("System Information:")
        info = self.system_info.get_info()
        return info
