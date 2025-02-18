from server import Base, engine

Base.metadata.create_all(bind=engine)
print("Tabelas criadas com sucesso!")
