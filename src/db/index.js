import mongoose from "mongoose";

const connectdb = async () => {
    try{
        await mongoose.connect(process.env.MONGOOSE_URI);
        console.log(" 👌 Mongodb Connect");
    } catch (error){
        console.error("Mongodb Connect error", error);
        process.exit(1);

    }
};

export default connectdb;