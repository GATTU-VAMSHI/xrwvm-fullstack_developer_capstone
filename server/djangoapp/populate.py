from .models import CarMake, CarModel


def initiate():
    car_make_data = [
        {"name": "NISSAN", "description": "Great cars. Japanese technology"},
        {"name": "Mercedes", "description": "Great cars. German technology"},
        {"name": "Audi", "description": "Great cars. German technology"},
        {"name": "Kia", "description": "Great cars. Korean technology"},
        {"name": "Toyota", "description": "Great cars. Japanese technology"},
    ]

    car_make_instances = []
    for data in car_make_data:
        car_make_instances.append(
            CarMake.objects.create(
                name=data['name'],
                description=data['description']
            )
        )

    car_model_data = [
        {"name": "Pathfinder", "type": "SUV", "year": 2023,
         "car_make": car_make_instances[0]},
        {"name": "Qashqai", "type": "SUV", "year": 2023,
         "car_make": car_make_instances[0]},
        {"name": "XTRAIL", "type": "SUV", "year": 2023,
         "car_make": car_make_instances[0]},
        {"name": "A-Class", "type": "SUV", "year": 2023,
         "car_make": car_make_instances[1]},
        # More car models...
    ]

    for data in car_model_data:
        CarModel.objects.create(
            name=data['name'],
            car_make=data['car_make'],
            type=data['type'],
            year=data['year']
        )
