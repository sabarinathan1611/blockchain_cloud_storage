class Converter:
    @staticmethod
    def convert_to_MB(size_in_bytes):
        return size_in_bytes / (1024 * 1024)

    @staticmethod
    def convert_to_KB(size_in_bytes):
        return size_in_bytes / 1024

    @staticmethod
    def convert_to_GB(size_in_bytes):
        return size_in_bytes / (1024 * 1024 * 1024)
        
    @staticmethod
    def calculate_percentage(size, total_size):
        percentage = (size / total_size) * 100
        return percentage