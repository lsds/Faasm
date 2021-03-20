import os
import time

import mxnet as mx
import horovod.mxnet as hvd
from mxnet import autograd, gluon, nd
from mxnet.test_utils import download

MOMENTUM = 0.9
DTYPE = "float32"
LEARNING_RATE = 0.01
GRADIENT_PREDIVIDE_FACTOR = 1.0
EPOCHS = 5
BATCH_SIZE = 64


# Function to get mnist iterator given a rank
def get_mnist_iterator(rank):
    data_dir = "faasm://data/mnist"

    train_img = os.join(data_dir, "train-images-idx3-ubyte")
    train_label = os.join(data_dir, "train-labels-idx1-ubyte")

    test_img = os.join(data_dir, "t10k-images-idx3-ubyte")
    test_label = os.join(data_dir, "t10k-labels-idx1-ubyte")

    input_shape = (1, 28, 28)

    train_iter = mx.io.MNISTIter(
        image=train_img,
        label=train_label,
        input_shape=input_shape,
        batch_size=BATCH_SIZE,
        shuffle=True,
        flat=False,
        num_parts=hvd.size(),
        part_index=hvd.rank(),
    )

    val_iter = mx.io.MNISTIter(
        image=test_img,
        label=test_label,
        input_shape=input_shape,
        batch_size=BATCH_SIZE,
        flat=False,
    )

    return train_iter, val_iter


# Function to define neural network
def conv_nets():
    net = gluon.nn.HybridSequential()
    with net.name_scope():
        net.add(gluon.nn.Conv2D(channels=20, kernel_size=5, activation="relu"))
        net.add(gluon.nn.MaxPool2D(pool_size=2, strides=2))
        net.add(gluon.nn.Conv2D(channels=50, kernel_size=5, activation="relu"))
        net.add(gluon.nn.MaxPool2D(pool_size=2, strides=2))
        net.add(gluon.nn.Flatten())
        net.add(gluon.nn.Dense(512, activation="relu"))
        net.add(gluon.nn.Dense(10))
    return net


# Function to evaluate accuracy for a model
def evaluate(model, data_iter, context):
    data_iter.reset()
    metric = mx.metric.Accuracy()
    for _, batch in enumerate(data_iter):
        data = batch.data[0].as_in_context(context)
        label = batch.label[0].as_in_context(context)
        output = model(data.astype(DTYPE, copy=False))
        metric.update([label], [output])

    return metric.get()


# Initialize Horovod
hvd.init()

# Horovod: pin context to local rank
context = mx.cpu(hvd.local_rank())
num_workers = hvd.size()

# Load training and validation data
train_data, val_data = get_mnist_iterator(hvd.rank())

# Build model
model = conv_nets()
model.cast(DTYPE)
model.hybridize()

# Create optimizer
optimizer_params = {
    "momentum": MOMENTUM,
    "learning_rate": LEARNING_RATE * hvd.size(),
}
opt = mx.optimizer.create("sgd", **optimizer_params)

# Initialize parameters
initializer = mx.init.Xavier(
    rnd_type="gaussian", factor_type="in", magnitude=2
)
model.initialize(initializer, ctx=context)

# Horovod: fetch and broadcast parameters
params = model.collect_params()
if params is not None:
    hvd.broadcast_parameters(params, root_rank=0)

# Horovod: create DistributedTrainer, a subclass of gluon.Trainer
trainer = hvd.DistributedTrainer(
    params, opt, gradient_predivide_factor=GRADIENT_PREDIVIDE_FACTOR
)

# Create loss function and train metric
loss_fn = gluon.loss.SoftmaxCrossEntropyLoss()
metric = mx.metric.Accuracy()

# Train model
for epoch in range(EPOCHS):
    tic = time.time()
    train_data.reset()
    metric.reset()
    for nbatch, batch in enumerate(train_data, start=1):
        data = batch.data[0].as_in_context(context)
        label = batch.label[0].as_in_context(context)
        with autograd.record():
            output = model(data.astype(DTYPE, copy=False))
            loss = loss_fn(output, label)
        loss.backward()
        trainer.step(BATCH_SIZE)
        metric.update([label], [output])

        if nbatch % 100 == 0:
            name, acc = metric.get()
            print(
                "[Epoch %d Batch %d] Training: %s=%f"
                % (epoch, nbatch, name, acc)
            )

    if hvd.rank() == 0:
        elapsed = time.time() - tic
        speed = nbatch * BATCH_SIZE * hvd.size() / elapsed
        print(
            "Epoch[%d]\tSpeed=%.2f samples/s\tTime cost=%f",
            epoch,
            speed,
            elapsed,
        )

    # Evaluate model accuracy
    _, train_acc = metric.get()
    name, val_acc = evaluate(model, val_data, context)
    if hvd.rank() == 0:
        print(
            "Epoch[%d]\tTrain: %s=%f\tValidation: %s=%f",
            epoch,
            name,
            train_acc,
            name,
            val_acc,
        )

    if hvd.rank() == 0 and epoch == EPOCHS - 1:
        assert val_acc > 0.96, (
            "Achieved accuracy (%f) is lower than expected\
                                (0.96)"
            % val_acc
        )
