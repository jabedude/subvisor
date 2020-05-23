int main(void)
{
    int sleep_time = 3;

    while (1) {
        printf("sleeping for %d...\n", sleep_time);
        sleep(sleep_time);
    }
    return 0;
}
