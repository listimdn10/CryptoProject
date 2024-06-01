from pymongo import MongoClient
import gridfs
from bson import ObjectId
import pprint
import datetime 

def upload_file(db, fs):
    file_path = input("Nhập đường dẫn đến file PDF bạn muốn upload: ")
    filename = input("Nhập tên bạn muốn gán cho file: ")
    
    try:
        with open(file_path, 'rb') as file_data:
            file_id = fs.put(file_data, filename=filename)
            print(f"File đã được upload với _id: {file_id} và tên: {filename}")
    except FileNotFoundError:
        print("Không tìm thấy file. Vui lòng kiểm tra lại đường dẫn.")
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

def download_file(db, fs):
    files = db.fs.files.find()
    print("Danh sách các file trong cơ sở dữ liệu 'test':")
    file_list = []
    for file in files:
        pprint.pprint(file)
        file_list.append(file)

    if not file_list:
        print("Không có file nào trong cơ sở dữ liệu.")
        return

    filename = input("Nhập tên file bạn muốn tải về: ")
    file = db.fs.files.find_one({"filename": filename})
    if not file:
        print(f"Không tìm thấy file với tên '{filename}' trong cơ sở dữ liệu.")
        return

    file_id = file['_id']
    output_filename = filename

    try:
        grid_out = fs.get(file_id)
        with open(output_filename, 'wb') as output_file:
            output_file.write(grid_out.read())

        print(f"File đã được tải về và lưu với tên {output_filename}")
    except gridfs.errors.NoFile:
        print(f"Không tìm thấy file với _id: {file_id} trong GridFS")
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

def find_file_by_name(db, partial_filename):
    regex_pattern = f".*{partial_filename}.*"
    files = db.fs.files.find({"filename": {"$regex": regex_pattern}})
    
    if files:
        print(f"Các file có tên chứa '{partial_filename}':")
        for file in files:
            print(file)
    else:
        print(f"Không có file nào có tên chứa '{partial_filename}' trong cơ sở dữ liệu.")

def find_file_by_date(db, date_str):
    date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
    files = db.fs.files.find({"uploadDate": {"$gte": date, "$lt": date + datetime.timedelta(days=1)}})
    
    if files:
        print("Các file tải lên vào ngày", date_str)
        for file in files:
            print(file)
    else:
        print(f"Không có file nào được tải lên vào ngày {date_str} trong cơ sở dữ liệu.")

def main():
    client = MongoClient('mongodb://localhost:27017/')
    db = client['test']
    fs = gridfs.GridFS(db)

    choice = input("Nhập: \n 'publish' để Publish file nếu bạn có quyền admin \n 'download' để download \n 'search_name' để tìm file theo tên \n 'search_date' để tìm file theo ngày: \n")

    if choice.lower() == 'publish':
        password = input("Nhập mật khẩu để publish file: ")
        if password == '@123admin':
            upload_file(db, fs)
        else:
            print("Bạn không có quyền publish file.")
    elif choice.lower() == 'download':
        download_file(db, fs)
    elif choice.lower() == 'search_name':
        filename = input("Nhập tên file bạn muốn tìm: ")
        find_file_by_name(db, filename)
    elif choice.lower() == 'search_date':
        date_str = input("Nhập ngày bạn muốn tìm (YYYY-MM-DD): ")
        find_file_by_date(db, date_str)
    else:
        print("Lựa chọn không hợp lệ.")

main()