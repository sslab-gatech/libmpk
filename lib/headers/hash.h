#define TABLE_SIZE 0x4000
template <typename T>


class HashEntry {
  private:
    int key;
    T value;
  public:
    HashEntry(int key, T value) {
      this->key = key;
      this->value = value;
    }
    int getKey() {
      return key;
    }
    T getValue() {
      return value;
    }
};

template <typename T>
class HashMap {
  private:
    HashEntry<T> **table;
  public:
    HashMap() {
      table = new HashEntry<T> * [TABLE_SIZE];
      for(int i = 0; i < TABLE_SIZE; i++)
        table[i] = NULL;
    }
    T get(int key) {
      int hash = (key % TABLE_SIZE);
      while (table[hash] != NULL && table[hash]->getKey() != key)
        hash = (hash + 1) % TABLE_SIZE;
      if (table[hash] == NULL)
        return NULL;
      else
        return table[hash]->getValue();
    }
    void put(int key, T value) {
      int hash = (key % TABLE_SIZE);
      while (table[hash] != NULL && table[hash]->getKey() != key)
        hash = (hash + 1) % TABLE_SIZE;
      if (table[hash] != NULL)
        delete table[hash];
      table[hash] = new HashEntry<T>(key, value);
    }
    ~HashMap() {
      for (int i = 0; i < TABLE_SIZE; i++)
        if (table[i] != NULL)
          delete table[i];
      delete[] table;
    }
};
