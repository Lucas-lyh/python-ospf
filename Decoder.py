import struct
import easydict

class Operator:
    def __init__(self):
        self.fields = []
        self.dataContainer = None

    @property
    def FMT(self)->str:
        return "!"+"".join([x[0] for x in self.fields])

    def decode(self, data:bytes):
        size = struct.calcsize(self.FMT)
        if len(data) < size:
            raise Exception("{} is too short for FMT {}".format(len(data), self.FMT))
        unpacked_data = struct.unpack(self.FMT, data[:size])
        tmp = {}
        for i in range(len(self.fields)):
            tmp[self.fields[i][1]] = unpacked_data[i]
        return easydict.EasyDict(tmp)

    def encode(self, *data, **dic):
        encode_values = list(data)
        try:
            encode_values += [dic[kv[0]] for kv in self.fields[len(encode_values):]]
        except:
            raise Exception("need data of {} but only get {}".format(self.fields[len(encode_values):], dic))
        if len(encode_values) != len(self.fields):
            raise Exception("data is not enough")
        return struct.pack(self.FMT, *encode_values)

    def get_len(self,data):
        return struct.calcsize(self.FMT)

    def next_data(self, data):
        return data[self.get_len(data):]

