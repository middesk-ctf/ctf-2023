# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the requirements file and install everything first so that it is
# cached and only needs to be installed if dependencies change.
COPY ./requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the templates and static files
COPY ./templates ./templates
COPY ./static ./static
# Copy the app into the container at /usr/src/app
COPY ./app.py ./init_app.py ./jwt.py ./entrypoint.sh ./

# Make port 3000 available to the world outside this container
EXPOSE 3000

# Run app.py when the container launches
CMD ["sh", "entrypoint.sh"]
