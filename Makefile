CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = -lresolv

# Répertoires
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Cibles et fichiers
TARGET = $(BIN_DIR)/dns_client
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Règle par défaut
all: $(TARGET)

# Création du binaire final
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Compilation des fichiers objets
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers générés
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Reconstruction complète
re: clean all

.PHONY: all clean re